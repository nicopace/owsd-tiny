/*
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/* creating proxy / stub objects on local bus, for use in remote ubus proxy */

#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <libwebsockets.h>

#include "local_stub.h"
#include "common.h"
#include "wsubus.impl.h"
#include "util_jsonrpc.h"
#include "util_ubus_blob.h"

/**
 * \brief ubus callback function called when method is called on stub object; routes call to the remote owsd via RPC
 */
static int wsu_local_stub_handle_call(struct ubus_context *ubus_ctx, struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *args)
{
	lwsl_notice("stub %s %s called\n", obj->name, method);

	// find stub object
	struct wsu_local_stub *stub = container_of(obj, struct wsu_local_stub, obj);

	char *args_json = blobmsg_format_json(args, true);
	json_object *args_jobj = args_json ? json_tokener_parse(args_json) : NULL;

	// extract local name from proxied name
	char *local_name = strchr(obj->name, '/')+1;

	// create RPC request
	char *d = jsonrpc__req_ubuscall(++stub->remote->call_id, wsu_remote_to_peer(stub->remote)->sid, local_name, method, args_jobj);

	free(args_json);
	json_object_put(args_jobj);

	// find slot for storing request id
	struct wsu_proxied_call *p = wsu_proxied_call_new(stub->remote);
	if (!p) {
		free(d);
		lwsl_err("Can't find slot to proxy call, max num calls %d", MAX_PROXIED_CALLS);
		return UBUS_STATUS_NOT_SUPPORTED;
	}

	// save id into slot
	p->jsonrpc_id = stub->remote->call_id;

	// ubus request will complete when matchin reply arrives
	ubus_defer_request(ubus_ctx, req, &p->ureq);

	// send out the RPC request
	wsu_queue_write_str(stub->remote->wsi, d);

	/* TODO: improvement in memory management
	* Do not free here.
	* Instead: use this already allocated memory in the wsu_writereq structure
	* in the wsu_queue_write_str function.
	* Also: free this memory together with the wsu_writereq
	*/
	free(d);

	return 0;
}

bool wsu_local_stub_is_same_signature(struct wsu_local_stub *stub, json_object *signature)
{
	// TODO validate signature jobj somewhere before this is called, we asume valid json

	if (stub->obj_type.n_methods != json_object_object_length(signature))
		return false;

	const struct ubus_method *m = stub->methods;
	json_object_object_foreach(signature, mname, margs) {
		if (m->n_policy != json_object_object_length(margs))
			return false;
		if (strcmp(m->name, mname))
			return false;

		const struct blobmsg_policy *b = m->policy;
		json_object_object_foreach(margs, aname, atype) {
			if (b->type != blobmsg_type_from_str(json_object_get_string(atype)))
				return false;
			if (strcmp(b->name, aname))
				return false;
			++b;
		}
		++m;
	}

	return true;
}

// {{{
// proxied_name functions are used for naming the remote events when replaying them locally
// and for naming the local objects

/**
 * \brief tells how much space to allocate for the proxied name based on the original name
 */
static size_t proxied_name_size(const struct wsu_remote_bus *remote, const char *name)
{
	// TODO maybe calculate space depending on length of remote's hostname or IP or some alias ...
	(void)remote;
	return strlen(name) + 50 + 2;
}

/**
 * \brief fills in caller-allocated string with name for the local stub objet. Based on the original name and the remote host
 *
 * \param proxied_name string to fill-in
 * \param proxied_name_sz size of string to fill-in
 * \param remote whose remote object/event we are naming
 * \param name the original bus name of the object or event
 */
static void proxied_name_fill(char *proxied_name, size_t proxied_name_sz, const struct wsu_remote_bus *remote, const char *name)
{
	lws_get_peer_simple(remote->wsi, proxied_name, proxied_name_sz);
	if(strncmp(proxied_name, "::ffff:", 7) == 0)
		memmove(proxied_name, proxied_name + 7, strlen(proxied_name) - 6);
	strncat(proxied_name, "/", proxied_name_sz - strlen(proxied_name));
	strncat(proxied_name, name, proxied_name_sz - strlen(proxied_name));
}

// }}}

struct wsu_local_stub* wsu_local_stub_create(struct wsu_remote_bus *remote, const char *object, json_object *signature)
{
	size_t num_methods = json_object_object_length(signature);
	size_t num_args = 0;
	{
		// first, count how much argument signatures in total there are for all methods of this object
		json_object_object_foreach(signature, mname, margs) {
			num_args += json_object_object_length(margs);
			(void)mname;
		}
	}

	// TODO validate signature jobj somewhere before this is called, we assume valid json
	// or inside here?

	// allocate space for stub info + method info, and for args info separately
	struct wsu_local_stub *stub = calloc(1, sizeof *stub + num_methods * sizeof stub->methods[0]);
	stub->method_args = calloc(num_args, sizeof stub->method_args[0]);

	// fill in fields
	stub->remote = remote;

	stub->obj.type = &stub->obj_type;
	stub->obj_type.n_methods = num_methods;
	stub->obj_type.methods = stub->methods;

	// deep copy all the argument names
	struct ubus_method *m = stub->methods;
	struct blobmsg_policy *b = stub->method_args;
	json_object_object_foreach(signature, mname, margs) {
		m->name = strdup(mname);
		m->n_policy = json_object_object_length(margs);
		m->policy = b;
		m->handler = wsu_local_stub_handle_call;

		json_object_object_foreach(margs, aname, atype) {
			b->type = blobmsg_type_from_str(json_object_get_string(atype));
			b->name = strdup(aname);
			++b;
		}
		++m;
	};

	// name the remote object
	size_t proxied_objname_sz = proxied_name_size(remote, object);
	char *proxied_objname = malloc(proxied_objname_sz);
	proxied_name_fill(proxied_objname, proxied_objname_sz, remote, object);

	stub->obj_type.name = proxied_objname;

	stub->obj.name = proxied_objname;
	stub->obj.type = &stub->obj_type;
	stub->obj.n_methods = stub->obj_type.n_methods;
	stub->obj.methods = stub->obj_type.methods;

	// insert into our collection
	stub->avl.key = strchr(proxied_objname, '/')+1;
	avl_insert(&remote->stubs, &stub->avl);

	// register the object on local bus
	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_add_object(global->ubus_ctx, &stub->obj);

	return stub;
}

void wsu_local_stub_destroy(struct wsu_local_stub *stub)
{
	// unregister object from bus
	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_remove_object(global->ubus_ctx, &stub->obj);

	// free up everything we deep-copied
	for (struct ubus_method *m = (struct ubus_method *)stub->obj_type.methods;
			m < stub->obj_type.methods + stub->obj_type.n_methods;
			++m) {
		for (struct blobmsg_policy *b = (struct blobmsg_policy *)m->policy;
				b < m->policy + m->n_policy;
				++b) {
			free((char*)b->name);
		}
		free((char*)m->name);
	}

	// remove from collection
	avl_delete(&stub->remote->stubs, &stub->avl);

	// free allocated memory
	free((char*)stub->obj_type.name);
	free(stub->method_args);
	free(stub);
}

struct wsu_local_proxied_event *wsu_local_proxied_event_create(struct wsu_remote_bus *remote, const char *event_name, json_object *event_data)
{
	// name the event
	size_t proxied_eventname_sz = proxied_name_size(remote, event_name);
	struct wsu_local_proxied_event *event = calloc(1, sizeof *event + proxied_eventname_sz);
	proxied_name_fill(event->name, proxied_eventname_sz, remote, event_name);

	// copy the event's data
	blob_buf_init(&event->b, 0);
	if (json_object_is_type(event_data, json_type_object))
		blobmsg_add_object(&event->b, event_data);

	return event;
}

void wsu_local_proxied_event_destroy(struct wsu_local_proxied_event *event)
{
	blob_buf_free(&event->b);
	free(event);
}
