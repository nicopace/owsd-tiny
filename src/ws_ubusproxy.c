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

/*
 * ubus RPC proxy over web socket
 */
#include "common.h"

#include "wsubus.h"
#include "wsubus.impl.h"
#include "wsubus_client.h"
#include "rpc.h"
#include "access_check.h"
#include "local_stub.h"
#include "util_jsonrpc.h"

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>

#include <libubus.h>
#include <libwebsockets.h>

#include <strings.h>
#include <errno.h>

static lws_callback_function ws_ubusproxy_cb;

struct lws_protocols ws_ubusproxy_proto = {
	WSUBUS_PROTO_NAME,
	ws_ubusproxy_cb,
	sizeof (struct wsu_peer),
	32768,    //3000 // arbitrary length
	0,    // - id
	NULL, // - user pointer
};

static int ws_ubusproxy_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct wsu_peer *peer = user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (wsubus_client_should_destroy(wsi))
			return -1;
			/* returning -1 from here initialises a tear down of the connection,
			  and LWS_CALLBACK_CLOSED will be called */

		lwsl_notice(WSUBUS_PROTO_NAME ": wsi %p writable now\n", wsi);
		return wsubus_tx_text(wsi);

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice(WSUBUS_PROTO_NAME ": closed\n");
		int role = peer->role;
		wsu_peer_deinit(wsi, peer);

		if (role == WSUBUS_ROLE_CLIENT)
			break;

		if (wsubus_client_should_destroy(wsi)) {
			wsubus_client_destroy(wsi);
		} else {
			wsubus_client_set_state(wsi, CONNECTION_STATE_DISCONNECTED);
			wsubus_client_reconnect(wsi);
		}
		break;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_notice(WSUBUS_PROTO_NAME ": peer closing\n");
		return 0;

		// proto init-destroy
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_info(WSUBUS_PROTO_NAME ": create proto\n");
		break;
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_info(WSUBUS_PROTO_NAME ": destroy proto\n");
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED: {
		if (wsubus_client_should_destroy(wsi))
			return -1;
		lwsl_info("connected as proxy\n");
		int rc = wsu_peer_init(peer, WSUBUS_ROLE_REMOTE);
		if (rc)
			return -1;

		wsubus_client_set_state(wsi, CONNECTION_STATE_CONNECTED);

		struct wsu_remote_bus *remote = &peer->u.remote;

		remote->wsi = wsi;
		memset(&remote->waiting_for, 0, sizeof remote->waiting_for);
		avl_init(&remote->stubs, avl_strcmp, false, NULL);

		// we use a fake "session ID" which tells remote owsd server to check our cert
		// instead of rpcd sessions
		wsu_sid_update(peer, "X-tls-certificate");

		// start listening for all events
		// (do a `ubus listen *`)
		char *d = jsonrpc__req_ubuslisten(++remote->call_id, peer->sid, "*");
		remote->waiting_for.listen = 1;
		wsu_queue_write_str(wsi, d);
		free(d);

		return 0;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct wsu_remote_bus *remote = wsi_to_remote(wsi);
		struct wsu_peer *peer = wsi_to_peer(wsi);

		// TODO maybe reuse tokener per client
		// and/or support JSON messages across multiple RECEIVE callbacks ?
		// If so, consider integrating this rx path + parsing logic with the wsubus rx path

		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		struct prog_context *prog = lws_context_user(lws_get_context(remote->wsi));

		lwsl_notice("received, len %zu < %.*s > \n", len, len > 200 ? 200 : (int)len, (char *)in);

		if (!jobj)
			goto out;

		json_object *id_jobj;
		json_object_object_get_ex(jobj, "id", &id_jobj);

		json_object *tmp;
		if (json_object_object_get_ex(jobj, "result", &tmp)) {
			// result came back
			// process it depending on what state we are in
			// (what sort of reply we are waiting for)
			if (remote->waiting_for.login) {
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_object_get_ex(tmp, "ubus_rpc_session", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					remote->waiting_for.login = 0;
					wsu_sid_update(peer, json_object_get_string(tmp));
				} else {
					// TODO maybe tear down, or try again. for now just skip
					lwsl_err("response to login not valid\n");
					goto out;
				}

				// valid response to login (contains ubus_rpc_session for us to use)
				char *d = jsonrpc__req_ubuslisten(++remote->call_id, peer->sid, "*");
				remote->waiting_for.listen = 1;
				wsu_queue_write_str(wsi, d);
				free(d);
			} else if (remote->waiting_for.listen) {
				// we are expecting a response to `ubus listen`
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))) {
					remote->waiting_for.listen = 0;
				} else {
					// TODO maybe tear down, or try agai.n for now just skip
					lwsl_err("response to ubus listen not valid\n");
					goto out;
				}

				// valid response to event came; now ask remote for ubus objects
				// (do a `ubus list *`)
				char *d = jsonrpc__req_ubuslist(++remote->call_id, peer->sid, "*");
				remote->waiting_for.list_id = remote->call_id;
				wsu_queue_write_str(wsi, d);
				free(d);
			} else if (remote->waiting_for.list_id
					&& json_object_is_type(id_jobj, json_type_int)
					&& json_object_get_int(id_jobj) == remote->waiting_for.list_id) {
				// we are expecting a response to `ubus list`
				if (
						json_object_is_type(tmp, json_type_array)
						&& !json_object_get_int(json_object_array_get_idx(tmp, 0))
						&& (tmp = json_object_array_get_idx(tmp, 1))
						&& json_object_is_type(tmp, json_type_object)) {
					// valid response to `ubus list` came back
					// now we have to register local stub objects corresponding to those from ubus list

					// Result of ubus list is sorted by name, as is our stub collection (avl tree).
					// We iterate through both collections and add what is missing from our stubs.
				
					int cmp_result = 1;
					struct wsu_local_stub *cur = NULL, *last = avl_last_element(&remote->stubs, last, avl), *next;
					{
						json_object_object_foreach(tmp, obj_name, obj_methods) {
							cur = avl_find_ge_element(&remote->stubs, obj_name, cur, avl);
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
							// check filters in wsubus_client
							// add the object only if it has a match
							if (!wsubus_client_match_pattern(obj_name))
								continue;
							lwsl_notice("create stub object for %s\n", obj_name);
							wsu_local_stub_create(remote, obj_name, obj_methods);
						} else if (!wsu_local_stub_is_same_signature(cur, obj_methods)) {
							lwsl_notice("signatures differ for %s\n", obj_name);
							// we have old version of object type / signature
							wsu_local_stub_destroy(cur);
							cur = next;
							// TODO could avoid realloc here if wsu_local_stub_create is converted to caller-allocated
							// check filters in wsubus_client
							// add the object only if it has a match
							if (!wsubus_client_match_pattern(obj_name))
								continue;
							lwsl_notice("create NEW stub object for %s\n", obj_name);
							wsu_local_stub_create(remote, obj_name, obj_methods);
						}
					}

					// FIXME when multiple object add events fire, only first one will be handled
					remote->waiting_for.list_id = 0;
				} else {
					// TODO maybe tear down, or try agai.n for now just skip
					lwsl_err("response to ubus list not valid, ignorind\n");
					goto out;
				}
			} else if (remote->waiting_for.call) {
				// we are expecting response to a call we are proxying from our stub object to remote owsd server
				int id;
				struct wsu_proxied_call *p = NULL;
				if (
						json_object_is_type(id_jobj, json_type_int)
						&& (id = json_object_get_int(id_jobj), 1) ) {
					lwsl_notice("got response to call %d \n", id);

					// search for that ID in our remote's proxied_calls collection
					wsu_proxied_call_foreach(remote, p) {
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
					ubus_send_reply(prog->ubus_ctx, &p->ureq, b.head);
					blob_buf_free(&b);
				}

				// send status code to resolve the pending request
				json_object *rc_jobj;
				if (
						json_object_is_type(tmp, json_type_array)
						&& (rc_jobj = json_object_array_get_idx(tmp, 0))
						&& json_object_is_type(rc_jobj, json_type_int)) {
					ubus_complete_deferred_request(prog->ubus_ctx, &p->ureq, json_object_get_int(rc_jobj));
				} else {
					ubus_complete_deferred_request(prog->ubus_ctx, &p->ureq, UBUS_STATUS_UNKNOWN_ERROR);
				}

				wsu_proxied_call_free(remote, p);
			}
		} else if (json_object_object_get_ex(jobj, "method", &tmp)) {
			// call or event happened on local bus, we need to proxy it to remote owsd server
			json_object *type_jobj;
			if (
					!strcmp("event", json_object_get_string(tmp))
					&& json_object_object_get_ex(jobj, "params", &tmp)
					&& json_object_is_type(tmp, json_type_object)
					&& json_object_object_get_ex(tmp, "type", &type_jobj)
					&& json_object_is_type(type_jobj, json_type_string)) {
				// event happened on local bus

				json_object_object_get_ex(tmp, "data", &tmp);
				if (
						!strcmp("ubus.object.add", json_object_get_string(type_jobj))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object was added on remote owsd's bus, look it up, when done, we'll add it

					if (!remote->waiting_for.list_id) {
						// FIXME: because we can't wait for multiple lists
						lwsl_warn("calling list again...\n");
					}

					char *d = jsonrpc__req_ubuslist(++remote->call_id, peer->sid, "*");
					remote->waiting_for.list_id = remote->call_id;
					wsu_queue_write_str(wsi, d);
					free(d);
				} else if (
						!strcmp("ubus.object.remove", json_object_get_string(type_jobj))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object removed, find and remove the matching stub

					struct wsu_local_stub *cur = avl_find_element(&remote->stubs, json_object_get_string(tmp), cur, avl);
					if (cur) {
						lwsl_notice("removing stub object for %s\n", (const char *)cur->avl.key);
						wsu_local_stub_destroy(cur);
					}
				} else {
					// plain old event happened, just replay / proxy it on local bus

					const char *eventname = json_object_get_string(type_jobj);

					struct wsu_local_proxied_event *event = wsu_local_proxied_event_create(remote, eventname, tmp);

					if (!event) {
						lwsl_err("error creating proxied event %s\n", eventname);
						return 0;
					}

					ubus_send_event(prog->ubus_ctx, event->name, event->b.head);
					wsu_local_proxied_event_destroy(event);
				}
			}
		}

out:
		if (jobj)
			json_object_put(jobj);

		json_tokener_free(jtok);
		
		return 0;
	}

	default:
		break;
	}
	return 0;
}
