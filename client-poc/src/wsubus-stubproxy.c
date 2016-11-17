/*
 * Copyright (C) 2016 Inteno Broadband Technology AB
 *
 * This software is the confidential and proprietary information of the
 * Inteno Broadband Technology AB. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the
 * license agreement you entered into with the Inteno Broadband Technology AB
 *
 * All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 */
/*
 * ubus over websocket - client session and message handling
 */
#include "common.h"
#include "wifiimport.h"
#include "wsubus.h"

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>
#include <json-c/json.h>

#include <libwebsockets.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#define WSUBUS_PROTO_NAME "ubus-json"

#define MAX_INFLIGHT_CALLS 20

#define lowest_zero_bit_1idx(X) ffs(~(X))
#define lowest_set_bit(X) ((X) & (-X))

static lws_callback_function wsubus_cb;

struct remote_ubus {
	int call_id;
	char sid[64];

	struct {
		unsigned int login  : 1;
		unsigned int listen : 1;
		unsigned int call   : MAX_INFLIGHT_CALLS;
		int list_id;
	} waiting_for;


	struct proxied_call {
		int jsonrpc_id;
		struct ubus_request_data ureq;
	} calls[MAX_INFLIGHT_CALLS];

	struct {
		unsigned char *data;
		size_t len;
	} write;

	struct lws *wsi;
	struct avl_tree stubs;
};

struct proxied_call *proxied_call_new(struct remote_ubus *remote)
{
	unsigned call_idx = lowest_zero_bit_1idx(remote->waiting_for.call);
	if (!call_idx || call_idx > MAX_INFLIGHT_CALLS) {
		return NULL;
	}
	--call_idx;

	remote->waiting_for.call |= (1U << call_idx);

	return &remote->calls[call_idx];
}

void proxied_call_free(struct remote_ubus *remote, struct proxied_call *p)
{
	int idx = p - remote->calls;
	if (idx >= 0 && idx < MAX_INFLIGHT_CALLS)
		remote->waiting_for.call &= ~(1U << idx);
}

#define proxied_call_foreach(REMOTE, P) \
	for (int _mask_##REMOTE = (REMOTE->waiting_for.call), _callbit_##REMOTE = lowest_set_bit(_mask_##REMOTE), _idx_##REMOTE; \
			(_callbit_##REMOTE = lowest_set_bit(_mask_##REMOTE)) \
			&& (_idx_##REMOTE = __builtin_ctz(_callbit_##REMOTE), P = &REMOTE->calls[_idx_##REMOTE], \
				_callbit_##REMOTE); \
			_mask_##REMOTE &= ~_callbit_##REMOTE)


struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct remote_ubus),
	655360, // arbitrary length
	0,    // - id
	NULL, // - user pointer
};

static char *make_jsonrpc_ubus_call(int id, const char *sid, const char *obj, const char *method, json_object *arg)
{
#if 0
	json_object *rpc = json_object_new_object();
	json_object_object_add(rpc, "jsonrpc", json_object_new_string("2.0"));
	json_object_object_add(rpc, "id", json_object_new_int(id));
	json_object_object_add(rpc, "method", json_object_new_string("call"));
	json_object *params = json_object_new_array();
	json_object_array_add(params, json_object_new_string(sid));
	json_object_object_add(rpc, "params", params);
#endif
	static char buf[2048];
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"call\","
			"\"params\":[\"%s\", \"%s\", \"%s\", %s]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			obj, method, arg ? json_object_to_json_string(arg) : "{}");
	return buf;
}

static char *make_jsonrpc_ubus_list(int id, const char *sid, const char *pattern)
{
	static char buf[2048];
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"list\","
			"\"params\":[\"%s\", \"%s\"]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			pattern);
	return buf;
}

static char *make_jsonrpc_ubus_listen(int id, const char *sid, const char *pattern)
{
	static char buf[2048];
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"subscribe\","
			"\"params\":[\"%s\", \"%s\"]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			pattern);
	return buf;
}

struct remote_stub {
	struct remote_ubus *remote;

	struct avl_node avl;

	struct blobmsg_policy *method_args;

	struct ubus_object obj;
	struct ubus_object_type obj_type;
	struct ubus_method methods[0];
};

int remote_stub_handle_call(struct ubus_context *ubus_ctx, struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *args)
{
	lwsl_notice("stub %s %s called\n", obj->name, method);
	lwsl_notice("obj name %s , path %s , type name %s\n", obj->name, obj->path, obj->type->name);

	struct remote_stub *stub = container_of(obj, struct remote_stub, obj);

	char *args_json = blobmsg_format_json(args, true);
	json_object *args_jobj = args_json ? json_tokener_parse(args_json) : NULL;

	char *local_name = strchr(obj->name, '/')+1;
	lwsl_notice("will call %s obj on ...\n", local_name);

	// TODO save req + id somewhere so we can respond
	// or reuse seq as id and to it that way?

	char *d = make_jsonrpc_ubus_call(++stub->remote->call_id, stub->remote->sid, local_name, method, args_jobj);

	free(args_json);

	if (stub->remote->write.data) {
		lwsl_err("writing in progress, can't proxy call\n");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	struct proxied_call *p = proxied_call_new(stub->remote);

	if (!p) {
		lwsl_err("Can't find slot to proxy call, max num calls %d", MAX_INFLIGHT_CALLS);
		return UBUS_STATUS_NOT_SUPPORTED;
	}

	p->jsonrpc_id = stub->remote->call_id;
	ubus_defer_request(ubus_ctx, req, &p->ureq);

	stub->remote->write.data = (unsigned char*)d;
	stub->remote->write.len = strlen(d);
	lws_callback_on_writable(stub->remote->wsi);

	return 0;
}

static enum blobmsg_type blobmsg_type_from_str(const char *c)
{
	return
		!c        ? __BLOBMSG_TYPE_LAST :
		*c == 'a' ? BLOBMSG_TYPE_ARRAY  :
		*c == 'o' ? BLOBMSG_TYPE_TABLE  :
		*c == 's' ? BLOBMSG_TYPE_STRING :
		*c == 'n' ? BLOBMSG_TYPE_INT32  :
		*c == 'b' ? BLOBMSG_TYPE_INT8   : BLOBMSG_TYPE_UNSPEC;
}

bool remote_stub_is_same_signature(struct remote_stub *stub, json_object *signature)
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

size_t proxied_name_size(const struct remote_ubus *remote, const char *name)
{
	(void)remote;
	return strlen(name) + INET6_ADDRSTRLEN + 2;
}

void proxied_name_fill(char *proxied_name, size_t proxied_name_sz, const struct remote_ubus *remote, const char *name)
{
	lws_get_peer_simple(remote->wsi, proxied_name, proxied_name_sz);
	strcat(proxied_name, "/");
	strcat(proxied_name, name);
	lwsl_notice("proxying remote name %s ad %s locally\n", name, proxied_name);
}

struct remote_stub* remote_stub_create(struct remote_ubus *remote, const char *object, json_object *signature)
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

	struct remote_stub *stub = calloc(1, sizeof *stub + num_methods * sizeof stub->methods[0]);
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
		m->handler = remote_stub_handle_call;

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

	lws_get_peer_simple(remote->wsi, proxied_objname, proxied_objname_sz);
	strcat(proxied_objname, "/");
	strcat(proxied_objname, object);

	stub->obj_type.name = proxied_objname;

	stub->obj.name = proxied_objname;
	stub->obj.type = &stub->obj_type;
	stub->obj.n_methods = stub->obj_type.n_methods;
	stub->obj.methods = stub->obj_type.methods;

	stub->avl.key = strchr(proxied_objname, '/')+1;
	avl_insert(&remote->stubs, &stub->avl);

	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_add_object(&global->ubus_ctx, &stub->obj);

	return stub;
}

void remote_stub_destroy(struct remote_stub *stub)
{
	struct prog_context *global = lws_context_user(lws_get_context(stub->remote->wsi));
	ubus_remove_object(&global->ubus_ctx, &stub->obj);

	avl_delete(&stub->remote->stubs, &stub->avl);
	free((char*)stub->obj_type.name);
	free(stub->method_args);
	free(stub);
}

static int wsubus_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct remote_ubus *remote = user;

	struct prog_context *global = lws_context_user(lws_get_context(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (ubus_connect_ctx(&global->ubus_ctx, global->ubus_path)) {
			lwsl_err("failed to connect to ubus\n");
			return -1;
		}
		ubus_add_uloop(&global->ubus_ctx);
		return 0;

	case LWS_CALLBACK_CLIENT_ESTABLISHED: {
		remote->wsi = wsi;
		memset(&remote->waiting_for, 0, sizeof remote->waiting_for);
		avl_init(&remote->stubs, avl_strcmp, false, NULL);

		remote->waiting_for.login = 1;

		json_object *adminadmin = json_object_new_object();
		json_object_object_add(adminadmin, "username", json_object_new_string("admin"));
		json_object_object_add(adminadmin, "password", json_object_new_string("admin"));

		char *d = make_jsonrpc_ubus_call(++remote->call_id, NULL, "session", "login", adminadmin);
		remote->write.data = (unsigned char*)d;
		remote->write.len = strlen(d);

		json_object_put(adminadmin);
		lws_callback_on_writable(wsi);

		return 0;
	}

	case LWS_CALLBACK_CLOSED:
		return 0;

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		lwsl_notice("received, len %d < %.*s > \n", len, len > 200 ? 200 : len, in);

		if (!jobj)
			goto out;

		json_object *id_jobj;
		json_object_object_get_ex(jobj, "id", &id_jobj);

		json_object *tmp;
		if (json_object_object_get_ex(jobj, "result", &tmp)) {
			// result came back
			if (remote->waiting_for.login) {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_object_get_ex(tmp, "ubus_rpc_session", &tmp)
						&& json_object_is_type(tmp, json_type_string)
				   ) {
					remote->waiting_for.login = 0;
					strcpy(remote->sid, json_object_get_string(tmp));
				} else {
					// TODO
					lwsl_err("response to login not valid\n");
					goto out;
				}

				char *d = make_jsonrpc_ubus_listen(++remote->call_id, remote->sid, "*");
				remote->write.data = (unsigned char*)d;
				remote->write.len = strlen(d);
				remote->waiting_for.listen = 1;
				lws_callback_on_writable(wsi);
			} else if (remote->waiting_for.listen) {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))) {
					remote->waiting_for.listen = 0;
				} else {
					// TODO
					lwsl_err("response to ubus listen not valid\n");
					goto out;
				}

				char *d = make_jsonrpc_ubus_list(++remote->call_id, remote->sid, "*");
				remote->write.data = (unsigned char*)d;
				remote->write.len = strlen(d);
				remote->waiting_for.list_id = remote->call_id;
				lws_callback_on_writable(wsi);
				break;
			} else if (remote->waiting_for.list_id
					&& json_object_is_type(id_jobj, json_type_int)
					&& json_object_get_int(id_jobj) == remote->waiting_for.list_id) {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_is_type(tmp, json_type_object)) {

					// iterate through our stubs as we iterate through listed objects,
					int cmp_result = 1;
					struct remote_stub *cur = NULL, *last = avl_last_element(&remote->stubs, last, avl), *next;
					{
						json_object_object_foreach(tmp, obj_name, obj_methods) {
							cur = avl_find_ge_element(&remote->stubs, obj_name, cur, avl);
							//lwsl_notice("after find, cur is %p\n", cur);
							if (cur)
								cmp_result = remote->stubs.comp(cur->avl.key, obj_name, remote->stubs.cmp_ptr);
							(void)obj_methods;
							break;
						}
					}

					json_object_object_foreach(tmp, obj_name, obj_methods) {
						if (cur) {
							// advance pointer cur until it's on or after objname
							avl_for_element_range_safe(cur, last, cur, avl, next) {
								cmp_result = remote->stubs.comp(cur->avl.key, obj_name, remote->stubs.cmp_ptr);
								if (cmp_result >= 0)
									break;
							}
						}

						if (cmp_result) {
							// we don't have that object proxied, create new
							lwsl_notice("create stub object for %s\n", obj_name);
							remote_stub_create(remote, obj_name, obj_methods);
						} else if (!remote_stub_is_same_signature(cur, obj_methods)) {
							lwsl_notice("signatures differ for %s\n", obj_name);
							// we have old version of object type / signature
							remote_stub_destroy(cur);
							cur = next;
							// TODO could avoid realloc here if remote_stub_create is converted to caller-allocated
							lwsl_notice("create NEW stub object for %s\n", obj_name);
							remote_stub_create(remote, obj_name, obj_methods);
						}
					}

					// FIXME when multiple object add events fire, only first one will be handled
					remote->waiting_for.list_id = 0;
				} else {
					// TODO
					lwsl_err("response to ubus list not valid, ignorind\n");
					goto out;
				}
			} else if (remote->waiting_for.call) {
				int id;
				struct proxied_call *p = NULL;
				if (
						json_object_is_type(id_jobj, json_type_int)
						&& (id = json_object_get_int(id_jobj), 1) ) {
					lwsl_notice("got response to call %d \n", id);

					proxied_call_foreach(remote, p) {
						if (p->jsonrpc_id == id) {
							break;
						} else {
							p = NULL;
						}
					}
				}

				if (!p) {
					lwsl_err("call id not found, ignoring\n");
					goto out;
				}

				struct prog_context *global = lws_context_user(lws_get_context(remote->wsi));
				// will send response to found request

				// send data if result contains any
				json_object *data_jobj;
				if (
						json_object_is_type(tmp, json_type_array)
						&& (data_jobj = json_object_array_get_idx(tmp, 1))
						&& json_object_is_type(data_jobj, json_type_object))  {
					struct blob_buf b = {};
					blob_buf_init(&b, 0);
					blobmsg_add_object(&b, data_jobj);
					ubus_send_reply(&global->ubus_ctx, &p->ureq, b.head);
					blob_buf_free(&b);
				}

				// send status code
				json_object *rc_jobj;
				if (
						json_object_is_type(tmp, json_type_array)
						&& (rc_jobj = json_object_array_get_idx(tmp, 0))
						&& json_object_is_type(rc_jobj, json_type_int)) {
					ubus_complete_deferred_request(&global->ubus_ctx, &p->ureq, json_object_get_int(rc_jobj));
				} else {
					ubus_complete_deferred_request(&global->ubus_ctx, &p->ureq, UBUS_STATUS_UNKNOWN_ERROR);
				}

				proxied_call_free(remote, p);
			}
		} else if (json_object_object_get_ex(jobj, "method", &tmp)) {
			// call or event came in, we need to proxy it
			json_object *type_jobj;
			if (
					!strcmp("event", json_object_get_string(tmp))
					&& json_object_object_get_ex(jobj, "params", &tmp)
					&& json_object_is_type(tmp, json_type_object)
					&& json_object_object_get_ex(tmp, "type", &type_jobj)
					&& json_object_is_type(type_jobj, json_type_string)) {
				json_object_object_get_ex(tmp, "data", &tmp);
				if (
						!strcmp("ubus.object.add", json_object_get_string(type_jobj))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object added, look it up, when done, we'll add it

					if (!remote->waiting_for.list_id) {
						// FIXME: because we can't wait for multiple lists
						lwsl_warn("calling list again...\n");
					}

					char *d = make_jsonrpc_ubus_list(++remote->call_id, remote->sid, "*");
					remote->write.data = (unsigned char*)d;
					remote->write.len = strlen(d);
					remote->waiting_for.list_id = remote->call_id;
					lws_callback_on_writable(wsi);
				} else if (
						!strcmp("ubus.object.remove", json_object_get_string(type_jobj))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object removed, lookup and remove
					struct remote_stub *cur = avl_find_element(&remote->stubs, json_object_get_string(tmp), cur, avl);
					if (cur) {
						lwsl_notice("removing stub object for %s\n", cur->avl.key);
						remote_stub_destroy(cur);
					}
				} else {
					struct blob_buf b = {};
					const char *eventname = json_object_get_string(type_jobj);

					size_t proxied_eventname_sz = proxied_name_size(remote, eventname);
					char *proxied_eventname = malloc(proxied_eventname_sz);
					proxied_name_fill(proxied_eventname, proxied_eventname_sz, remote, eventname);

					blob_buf_init(&b, 0);
					if (json_object_is_type(tmp, json_type_object))
						blobmsg_add_object(&b, tmp);
					ubus_send_event(&global->ubus_ctx, proxied_eventname, b.head);
					blob_buf_free(&b);
					free(proxied_eventname);
				}
			}
		}

out:
		if (jobj)
			json_object_put(jobj);

		json_tokener_free(jtok);
		
		return 0;
	}

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		if (remote->write.data) {
			lwsl_notice("sending, len %d < %.*s> \n", remote->write.len, remote->write.len, remote->write.data);
			int ret = (int)remote->write.len != lws_write(wsi, remote->write.data, remote->write.len, LWS_WRITE_TEXT);
			remote->write.data = NULL;
			remote->write.len = 0;
			return ret;
		} else {
			return -1;
		}
	}

	default:
		return 0;
	}
	return 0;
}

