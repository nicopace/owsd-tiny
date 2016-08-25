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

#include <json-c/json.h>

#include <libwebsockets.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#define WSUBUS_PROTO_NAME "ubus-json"

static lws_callback_function wsubus_cb;

struct wsubus_client_session {

	enum {
		DEFAULT,
		WAIT_LISTENOK,
		LISTENING,
		BUSY,
	} state;

	struct {
		unsigned char *data;
		size_t len;
	} write;
};

struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct wsubus_client_session),
	0,    //3000 // arbitrary length
	0,    // - id
	NULL, // - user pointer
};

static char *make_listen_rpc(const char *name)
{
	static char buf[128];
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":1,"
			"\"method\":\"subscribe\","
			"\"params\":[\"%s\", \"%s\"]"
			"}",
			"00000000000000000000000000000000",
			name);
	return buf;
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

		char *d = make_listen_rpc("wireless.credentials");
		client->write.data = (unsigned char*)d;
		client->write.len = strlen(d);

		lws_callback_on_writable(wsi);

		client->state = WAIT_LISTENOK;

		return 0;

	case LWS_CALLBACK_CLOSED:
		return 0;

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		if (jobj && client->state == WAIT_LISTENOK) {
			struct json_object *tmp;
			if (
					json_object_object_get_ex(jobj, "result", &tmp) &&
					json_object_is_type(tmp, json_type_array) &&
					!json_object_get_int(json_object_array_get_idx(tmp, 0)) ) {
				client->state = LISTENING;
			} else {
				// TODO
				lwsl_err("invalid response to event listen\n");
			}
		} else if (jobj && client->state == LISTENING) {
			struct json_object *p, *q;
			if ( json_object_object_get_ex(jobj, "method", &p)
					&& json_object_is_type(p, json_type_string)
					&& !strcmp("event", json_object_get_string(p))

					&& json_object_object_get_ex(jobj, "params", &p)
					&& json_object_is_type(p, json_type_object)
					&& json_object_object_get_ex(p, "type", &q)
					&& json_object_is_type(q, json_type_string)
					&& !strcmp("wireless.credentials", json_object_get_string(q))

					&& json_object_object_get_ex(p, "data", &q)
					&& json_object_is_type(q, json_type_object)

#if 0
					&& (p = q)
					&& json_object_object_get_ex(p, "ssid", &p)
					&& json_object_is_type(p, json_type_string)
					&& json_object_object_get_ex(q, "key", &q)
					&& json_object_is_type(q, json_type_string)
#endif
			   ) {
				exec_wifi_import(q);
			} else {
				// TODO
				lwsl_err("response not valid event\n");
			}
		}

		if (jobj)
			json_object_put(jobj);

		json_tokener_free(jtok);
		
		return 0;
	}

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		if (client->write.data) {
			lwsl_notice("writing %.*s", (int)client->write.len, client->write.data);
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

