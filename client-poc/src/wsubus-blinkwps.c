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

struct wsubus_client_session {
	int call_id;
	char sid[64];

	enum {
		DEFAULT,
		WAIT_LOGINOK,
		WAIT_LEDGET,
		WAIT_LEDSET,
	} state;

	enum {
		LED_ON,
		LED_OFF
	} led_state;

	struct {
		unsigned char *data;
		size_t len;
	} write;

	struct lws *wsi;

	struct uloop_timeout utimer;
};

struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct wsubus_client_session),
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

void timer_blink_cb(struct uloop_timeout *utimer)
{
	struct wsubus_client_session *client = container_of(utimer, struct wsubus_client_session, utimer);

	char *d = make_jsonrpc_ubus_call(client->call_id, client->sid, "led.wps", "status", NULL);
	client->write.data = (unsigned char*)d;
	client->write.len = strlen(d);
	client->state = WAIT_LEDGET;
	lws_callback_on_writable(client->wsi);
}

static int wsubus_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct wsubus_client_session *client = user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		client->state = DEFAULT;
		client->call_id = 1;

		json_object *adminadmin = json_object_new_object();
		json_object_object_add(adminadmin, "username", json_object_new_string("admin"));
		json_object_object_add(adminadmin, "password", json_object_new_string("admin"));

		char *d = make_jsonrpc_ubus_call(client->call_id, NULL, "session", "login", adminadmin);
		client->write.data = (unsigned char*)d;
		client->write.len = strlen(d);

		client->wsi = wsi;
		client->utimer.cb = timer_blink_cb;

		json_object_put(adminadmin);
		lws_callback_on_writable(wsi);

		client->state = WAIT_LOGINOK;

		return 0;

	case LWS_CALLBACK_CLOSED:
		return 0;

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		lwsl_notice("received, len %d < %.*s > \n\n", len, len, in);

		if (jobj && client->state == WAIT_LOGINOK) {
			struct json_object *tmp;
			if (
					json_object_object_get_ex(jobj, "result", &tmp)
					&& json_object_is_type(tmp, json_type_array)
					&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
					&& (tmp = json_object_array_get_idx(tmp, 1))
					&& json_object_object_get_ex(tmp, "ubus_rpc_session", &tmp)
					&& json_object_is_type(tmp, json_type_string)
					) {
				strcpy(client->sid, json_object_get_string(tmp));

				uloop_timeout_add(&client->utimer);
				uloop_timeout_set(&client->utimer, 0);
			} else {
				// TODO
				lwsl_err("response to login not valid\n");
				//return -1;
			}
		} else if (jobj && client->state == WAIT_LEDGET) {
			struct json_object *tmp;
			if ( 
					json_object_object_get_ex(jobj, "result", &tmp)
					&& json_object_is_type(tmp, json_type_array)
					&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
					&& (tmp = json_object_array_get_idx(tmp, 1))
					&& json_object_object_get_ex(tmp, "state", &tmp)
					&& json_object_is_type(tmp, json_type_string)
					) {
				client->led_state = strcmp(json_object_get_string(tmp), "ok") ? LED_OFF : LED_ON;

				tmp = json_object_new_object();
				json_object_object_add(tmp, "state", json_object_new_string(client->led_state == LED_ON ? "off" : "ok"));

				char *d = make_jsonrpc_ubus_call(client->call_id, client->sid, "led.wps", "set", tmp);
				json_object_put(tmp);
				client->write.data = (unsigned char*)d;
				client->write.len = strlen(d);
				client->state = WAIT_LEDSET;
				lws_callback_on_writable(wsi);
			} else {
				// TODO
				lwsl_err("response to led status not valid\n");
				return -1;
			}
		} else if (jobj && client->state == WAIT_LEDSET) {
			struct json_object *tmp;
			if ( 
					json_object_object_get_ex(jobj, "result", &tmp)
					&& json_object_is_type(tmp, json_type_array)
					&& !json_object_get_int(json_object_array_get_idx(tmp, 0)) 
			   ) {
				uloop_timeout_set(&client->utimer, 5000);
			} else {
				lwsl_err("response to led set not valid\n");
			}
		}

		if (jobj)
			json_object_put(jobj);

		json_tokener_free(jtok);
		
		return 0;
	}

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		if (client->write.data) {
			lwsl_notice("sending, len %d < %.*s> \n\n", client->write.len, client->write.len, client->write.data);
			return (int)client->write.len != lws_write(wsi, client->write.data, client->write.len, LWS_WRITE_TEXT);
		} else {
			return -1;
		}
	}

	default:
		return 0;
	}
	return 0;
}

