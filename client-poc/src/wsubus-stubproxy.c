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

#include <json-c/json.h>

#include <libwebsockets.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#define WSUBUS_PROTO_NAME "ubus-json"

static lws_callback_function wsubus_cb;

struct ubus_remote {
	int call_id;
	char sid[64];

	enum {
		W8ing4_NONE = 0,
		W8ing4_LOGIN,
		W8ing4_LISTEN,
		W8ing4_LIST,
	} waiting_for;

	struct {
		unsigned char *data;
		size_t len;
	} write;

	struct lws *wsi;
};

struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct ubus_remote),
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

void remote_stub_create(struct ubus_remote *remote, const char *object, json_object *signature)
{
	struct ubus_method *mets = calloc(json_object_object_length(signature), sizeof *mets), *m;
	m = mets;

	json_object_object_foreach(signature, mname, margs) {
		m->name = mname;
		m->policy = calloc(json_object_object_length(margs), sizeof *m->policy);
		struct blobmsg_policy *b = (struct blobmsg_policy*)m->policy;
		json_object_object_foreach(margs, aname, atype) {
			char c = json_object_get_string(atype)[0];
			b->type = (
					c == 'a' ? BLOBMSG_TYPE_ARRAY  :
					c == 'o' ? BLOBMSG_TYPE_TABLE  :
					c == 's' ? BLOBMSG_TYPE_STRING :
					c == 'n' ? BLOBMSG_TYPE_INT32  :
					c == 'b' ? BLOBMSG_TYPE_INT8   : BLOBMSG_TYPE_UNSPEC);
			b->name = aname;
			++b;
		}
		++m;
	};

	struct ubus_object *obj = calloc(1, sizeof *obj);
	char *objname = malloc(strlen(object) + INET6_ADDRSTRLEN + 2);

	objname[0] = '\0';
	strcat(objname, "REMOTE/");
	strcat(objname, object);

	obj->name = objname;
	obj->methods = mets;

	// TODO attach obj somewhere to track it

	struct prog_context *global = lws_context_user(lws_get_context(remote->wsi));

	int rc = ubus_add_object(&global->ubus_ctx, obj);

	lwsl_notice("adding ubus object %s -> RC %d\n", objname, rc);
}

void remote_stub_destroy(struct ubus_remote *remote, const char *object)
{
	// TODO find object and remove it, free memory
}

static int wsubus_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct ubus_remote *remote = user;

	struct prog_context *global = lws_context_user(lws_get_context(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (ubus_connect_ctx(&global->ubus_ctx, global->ubus_path)) {
			lwsl_err("failed to connect to ubus\n");
			return -1;
		}
		return 0;

	case LWS_CALLBACK_CLIENT_ESTABLISHED: {
		json_object *adminadmin = json_object_new_object();
		json_object_object_add(adminadmin, "username", json_object_new_string("admin"));
		json_object_object_add(adminadmin, "password", json_object_new_string("admin"));

		char *d = make_jsonrpc_ubus_call(remote->call_id, NULL, "session", "login", adminadmin);
		remote->write.data = (unsigned char*)d;
		remote->write.len = strlen(d);

		remote->wsi = wsi;

		json_object_put(adminadmin);
		lws_callback_on_writable(wsi);

		remote->waiting_for = W8ing4_LOGIN;

		return 0;
	}

	case LWS_CALLBACK_CLOSED:
		return 0;

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		lwsl_notice("received, len %d < %.*s > \n\n", len, len, in);

		if (!jobj)
			goto out;

		struct json_object *tmp;
		if (json_object_object_get_ex(jobj, "result", &tmp)) {
			// result came back
			switch (remote->waiting_for) {
			case W8ing4_LOGIN: {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_object_get_ex(tmp, "ubus_rpc_session", &tmp)
						&& json_object_is_type(tmp, json_type_string)
				   ) {
					strcpy(remote->sid, json_object_get_string(tmp));
				} else {
					// TODO
					lwsl_err("response to login not valid\n");
					goto out;
				}

				char *d = make_jsonrpc_ubus_listen(++remote->call_id, remote->sid, "*");
				remote->write.data = (unsigned char*)d;
				remote->write.len = strlen(d);
				remote->waiting_for = W8ing4_LISTEN;
				lws_callback_on_writable(wsi);

				break;
			}
			case W8ing4_LISTEN: {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))) {
					;
				} else {
					// TODO
					lwsl_err("response to ubus listen not valid\n");
					goto out;
				}

				char *d = make_jsonrpc_ubus_list(++remote->call_id, remote->sid, "*");
				remote->write.data = (unsigned char*)d;
				remote->write.len = strlen(d);
				remote->waiting_for = W8ing4_LIST;
				lws_callback_on_writable(wsi);
				break;
			}
			case W8ing4_LIST: {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_is_type(tmp, json_type_object)) {
					json_object_object_foreach(tmp, obj_name, obj_methods) {
						remote_stub_create(remote, obj_name, obj_methods);
					}
				}

				// FIXME when multiple object add events fire, only first one will be handled
				remote->waiting_for = 0;
				break;
			}

			case 0:
			default:
				break;
			}
		} else if (json_object_object_get_ex(jobj, "method", &tmp)) {
			json_object *t;
			if (
					!strcmp("event", json_object_get_string(tmp))
					&& json_object_object_get_ex(jobj, "params", &tmp)
					&& json_object_is_type(tmp, json_type_object)
					&& json_object_object_get_ex(tmp, "type", &t)
					&& json_object_is_type(t, json_type_string)
					&& json_object_object_get_ex(tmp, "data", &tmp)) {
				// object add/remove event
				if (
						!strcmp("ubus.object.add", json_object_get_string(t))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object added, look it up, when done

#if 0
					char *d = make_jsonrpc_ubus_list(++remote->call_id, remote->sid, json_object_get_string(tmp));
					remote->write.data = (unsigned char*)d;
					remote->write.len = strlen(d);
					remote->waiting_for = W8ing4_LIST;
					lws_callback_on_writable(wsi);
#endif
					// FIXME: above should be used, but below is workaround because we can't wait for multiple lists
					if (0 == (remote->waiting_for & W8ing4_LIST)) {
						char *d = make_jsonrpc_ubus_list(++remote->call_id, remote->sid, "*");
						remote->write.data = (unsigned char*)d;
						remote->write.len = strlen(d);
						remote->waiting_for = W8ing4_LIST;
						lws_callback_on_writable(wsi);
					}
				} else if (
						!strcmp("ubus.object.remove", json_object_get_string(t))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					remote_stub_destroy(remote, json_object_get_string(tmp));
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
			lwsl_notice("sending, len %d < %.*s> \n\n", remote->write.len, remote->write.len, remote->write.data);
			return (int)remote->write.len != lws_write(wsi, remote->write.data, remote->write.len, LWS_WRITE_TEXT);
		} else {
			return -1;
		}
	}

	default:
		return 0;
	}
	return 0;
}

