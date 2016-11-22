#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <libwebsockets.h>

#include "local_stub.h"
#include "common.h"
#include "wsubus.impl.h"
#include "util_jsonrpc.h"
#include "util_ubus_blob.h"

static int wsu_local_stub_handle_call(struct ubus_context *ubus_ctx, struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *args)
{
	lwsl_notice("stub %s %s called\n", obj->name, method);

	struct wsu_local_stub *stub = container_of(obj, struct wsu_local_stub, obj);

	char *args_json = blobmsg_format_json(args, true);
	json_object *args_jobj = args_json ? json_tokener_parse(args_json) : NULL;

	char *local_name = strchr(obj->name, '/')+1;

	char *d = jsonrpc__req_ubuscall(++stub->remote->call_id, wsu_remote_to_peer(stub->remote)->sid, local_name, method, args_jobj);

	free(args_json);

	struct wsu_proxied_call *p = wsu_proxied_call_new(stub->remote);

	if (!p) {
		lwsl_err("Can't find slot to proxy call, max num calls %d", MAX_PROXIED_CALLS);
		return UBUS_STATUS_NOT_SUPPORTED;
	}

	p->jsonrpc_id = stub->remote->call_id;
	ubus_defer_request(ubus_ctx, req, &p->ureq);

	wsu_queue_write_str(stub->remote->wsi, d);

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

static size_t proxied_name_size(const struct wsu_remote_bus *remote, const char *name)
{
	(void)remote;
	return strlen(name) + 50 + 2;
}

static void proxied_name_fill(char *proxied_name, size_t proxied_name_sz, const struct wsu_remote_bus *remote, const char *name)
{
	lws_get_peer_simple(remote->wsi, proxied_name, proxied_name_sz);
	strcat(proxied_name, "/");
	strcat(proxied_name, name);
}


struct wsu_local_stub* wsu_local_stub_create(struct wsu_remote_bus *remote, const char *object, json_object *signature)
{
	size_t num_methods = json_object_object_length(signature);
	size_t num_args = 0;
	{
		json_object_object_foreach(signature, mname, margs) {
			num_args += json_object_object_length(margs);
			(void)mname;
		}
	}

	// TODO validate signature jobj somewhere before this is called, we asume valid json

	struct wsu_local_stub *stub = calloc(1, sizeof *stub + num_methods * sizeof stub->methods[0]);
	stub->method_args = calloc(num_args, sizeof stub->method_args[0]);
	stub->remote = remote;

	stub->obj.type = &stub->obj_type;
	stub->obj_type.n_methods = num_methods;
	stub->obj_type.methods = stub->methods;

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

	size_t proxied_objname_sz = proxied_name_size(remote, object);
	char *proxied_objname = malloc(proxied_objname_sz);
	proxied_name_fill(proxied_objname, proxied_objname_sz, remote, object);

	stub->obj_type.name = proxied_objname;

	stub->obj.name = proxied_objname;
	stub->obj.type = &stub->obj_type;
	stub->obj.n_methods = stub->obj_type.n_methods;
	stub->obj.methods = stub->obj_type.methods;

	stub->avl.key = strchr(proxied_objname, '/')+1;
	avl_insert(&remote->stubs, &stub->avl);

	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_add_object(global->ubus_ctx, &stub->obj);

	return stub;
}

void wsu_local_stub_destroy(struct wsu_local_stub *stub)
{
	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_remove_object(global->ubus_ctx, &stub->obj);

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

	avl_delete(&stub->remote->stubs, &stub->avl);
	free((char*)stub->obj_type.name);
	free(stub->method_args);
	free(stub);
}

struct wsu_local_proxied_event *wsu_local_proxied_event_create(struct wsu_remote_bus *remote, const char *event_name, json_object *event_data)
{
	size_t proxied_eventname_sz = proxied_name_size(remote, event_name);
	struct wsu_local_proxied_event *event = calloc(1, sizeof *event + proxied_eventname_sz);

	proxied_name_fill(event->name, proxied_eventname_sz, remote, event_name);

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
