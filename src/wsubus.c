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

#include "wsubus.h"
#include "wsubus.impl.h"
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
#include <assert.h>
#include <fnmatch.h>

#define WSUBUS_PROTO_NAME "ubus-json"

static lws_callback_function wsubus_cb;

struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct wsu_peer),
	32768,    //3000 // arbitrary length
	0,    // - id
	NULL, // - user pointer
};

static bool origin_allowed(struct list_head *origin_list, char *origin)
{
	struct origin *origin_el;

	list_for_each_entry(origin_el, origin_list, list) {
		if (!fnmatch(origin_el->url, origin, 0))
			return true;
	}

	return false;
}

static int wsubus_filter(struct lws *wsi)
{
	int len = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) + 1;
	assert(len > 0);
	char *origin = malloc((size_t)len);

	if (!origin) {
		lwsl_err("error allocating origin header: %s\n", strerror(errno));
		return -1;
	}
	origin[len-1] = '\0';

	int rc = 0;
	int e;

	struct vh_context *vc;

	if (len == 0) {
		lwsl_err("no or empty origin header\n");
		rc = -2;
	} else if ((e = lws_hdr_copy(wsi, origin, len, WSI_TOKEN_ORIGIN)) < 0) {
		lwsl_err("error copying origin header %d\n", e);
		rc = -3;
	} else if (!(vc = lws_protocol_vh_priv_get(
				lws_get_vhost(wsi),
				lws_get_protocol(wsi)))) {
		lwsl_err("no list of origins%d\n");
		rc = -4;
	} else if (!origin_allowed(&vc->origins, origin)) {
		lwsl_err("origin %s not allowed\n", origin);
		rc = -5;
	}

	free(origin);
	return rc;
}

static inline int wsu_peer_init(struct wsu_peer *peer, enum wsu_role role)
{
	if (role == WSUBUS_ROLE_CLIENT) {
		static unsigned int clientid = 1;

		peer->u.client.id = clientid++;
		INIT_LIST_HEAD(&peer->u.client.rpc_call_q);
		INIT_LIST_HEAD(&peer->u.client.access_check_q);
	} else if (role ==  WSUBUS_ROLE_REMOTE) {
	} else {
		return -1;
	}

	peer->role = role;

	struct json_tokener *jtok = json_tokener_new();

	if (!jtok)
		return 1;

	peer->curr_msg.len = 0;
	peer->curr_msg.jtok = jtok;
	INIT_LIST_HEAD(&peer->write_q);

	peer->sid[0] = '\0';
	return 0;
}

static void wsu_peer_deinit(struct lws *wsi, struct wsu_peer *peer)
{
	json_tokener_free(peer->curr_msg.jtok);
	peer->curr_msg.jtok = NULL;

	{
		struct wsu_writereq *p, *n;
		list_for_each_entry_safe(p, n, &peer->write_q, wq) {
			lwsl_info("free write in progress %p\n", p);
			list_del(&p->wq);
			free(p);
		}
	}

	if (peer->role == WSUBUS_ROLE_CLIENT) {
		struct prog_context *prog = lws_context_user(lws_get_context(wsi));

		wsubus_unsubscribe_all_by_wsi(wsi);

		{
			struct wsubus_client_access_check_ctx *p, *n;
			list_for_each_entry_safe(p, n, &peer->u.client.access_check_q, acq) {
				lwsl_info("free check in progress %p\n", p);
				list_del(&p->acq);
				wsubus_access_check__cancel(prog->ubus_ctx, p->req);
				if (p->destructor)
					p->destructor(p);
			}
		}

		{
			struct list_head *p, *n;
			list_for_each_safe(p, n, &peer->u.client.rpc_call_q) {
				list_del(p);
				wsubus_percall_ctx_destroy_h(p);
				lwsl_info("free call in progress %p\n", p);
			}
		}
	} else if (peer->role == WSUBUS_ROLE_REMOTE) {
		struct wsu_local_stub *cur, *next;
		avl_for_each_element_safe(&peer->u.remote.stubs, cur, avl, next) {
			wsu_local_stub_destroy(cur);
		}
	}
}

static void wsu_on_msg_from_client(struct lws *wsi,
		struct blob_attr *blob)
{
	const struct wsu_client_session *client = wsi_to_client(wsi);
	lwsl_info("client %u handling blobmsg buf\n", client->id);
	(void)client;

	struct jsonrpc_blob_req *jsonrpc_req = malloc(sizeof *jsonrpc_req);
	struct ubusrpc_blob *ubusrpc_req = malloc(sizeof *ubusrpc_req);

	int e = 0;
	if (!jsonrpc_req || !ubusrpc_req) {
		// free of NULL is no-op so okay
		lwsl_err("failed to alloc\n");
		e = JSONRPC_ERRORCODE__INTERNAL_ERROR;
		goto out;
	}

	if (jsonrpc_blob_req_parse(jsonrpc_req, blob) != 0) {
		lwsl_info("blobmsg not valid jsonrpc\n");
		e = JSONRPC_ERRORCODE__INVALID_REQUEST;
		goto out;
	}

	if ((e = ubusrpc_blob_parse(ubusrpc_req, jsonrpc_req->method, jsonrpc_req->params)) != 0) {
		lwsl_info("not valid ubus rpc in jsonrpc %d\n", e);
		goto out;
	}

	if (ubusrpc_req->handler(wsi, ubusrpc_req, jsonrpc_req->id) != 0) {
		lwsl_info("ubusrpc method handler failed\n");
		e = JSONRPC_ERRORCODE__OTHER;
		goto out;
	}

out:
	// send jsonrpc error code if we failed...
	if (e) {
		char *json_str = jsonrpc__resp_error(jsonrpc_req ? jsonrpc_req->id : NULL, e, NULL);
		wsu_queue_write_str(wsi, json_str);
		free(json_str);
		free(ubusrpc_req);
	}

	free(jsonrpc_req);
	return;
}

static void wsubus_rx_json(struct lws *wsi,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = lws_remaining_packet_payload(wsi);
	int is_final_frame = lws_is_final_fragment(wsi);
	struct wsu_peer *peer = wsi_to_peer(wsi);

	assert(len < INT32_MAX);
	peer->curr_msg.len += len;

	struct json_object *jobj = json_tokener_parse_ex(peer->curr_msg.jtok, in, (int)len);

	enum json_tokener_error tok_error = json_tokener_get_error(peer->curr_msg.jtok);
	int parsed_to = peer->curr_msg.jtok->char_offset;

	if (!remaining_bytes_in_frame && is_final_frame) {
		if (parsed_to == (int)len && jobj && json_object_is_type(jobj, json_type_object)) {
			struct blob_buf blob = {};
			blob_buf_init(&blob, 0);
			blobmsg_add_object(&blob, jobj);
			wsu_on_msg_from_client(wsi, blob.head);
			blob_buf_free(&blob);
		} else {
			// parse error -> we just ignore the message
			lwsl_err("json parsing error %s, at char %d of %u, dropping msg\n",
					json_tokener_error_desc(tok_error), parsed_to, len);
			char *resp = jsonrpc__resp_error(NULL, JSONRPC_ERRORCODE__PARSE_ERROR, NULL);
			wsu_queue_write_str(wsi, resp);
			free(resp);
		}
		wsu_read_reset(peer);
	} else {
		if (tok_error != json_tokener_continue) {
			// parse error mid-message, client will send more data
			// For now we drop the client, but we could mark state and skip only this message
			lwsl_err("unexpected json parsing error %s\n", json_tokener_error_desc(tok_error));
			lwsl_err("Dropping client\n");

			// TODO<lwsclose> check
			// stop reading and writing
			shutdown(lws_get_socket_fd(wsi), SHUT_RDWR);
		}
	}

	if (jobj)
		json_object_put(jobj);
}

static void wsubus_rx_blob(struct lws *wsi,
		const char *in,
		size_t len)
{
	// TODO implement
	lwsl_err("Binary (blobmsg) not implemented %p %p %zu\n", wsi, in, len);
	// for now just do nothing with binary message
}

static void wsubus_rx(struct lws *wsi,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = lws_remaining_packet_payload(wsi);
	int is_final_frame = lws_is_final_fragment(wsi);

	struct wsu_peer *peer = wsi_to_peer(wsi);

	lwsl_info("peer IO: msg final %d, len was %zu , remaining %zu\n", is_final_frame, len, remaining_bytes_in_frame);
	(void)is_final_frame;

	if (len > WSUBUS_MAX_MESSAGE_LEN || remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN ||
			peer->curr_msg.len + len + remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN) {
		// client intends to send too mush data, we will drop them
		lwsl_err("peer IO: received fragment of frame (%zu total) making msg too long\n",
				len + remaining_bytes_in_frame);

		// TODO<lwsclose> check
		// stop reading from mad client
		shutdown(lws_get_socket_fd(wsi), SHUT_RD);
	}

	if (lws_frame_is_binary(wsi)) {
		wsubus_rx_blob(wsi, in, len);
	} else {
		wsubus_rx_json(wsi, in, len);
	}
}

static int wsubus_tx_text(struct lws *wsi)
{
	struct wsu_peer *peer = wsi_to_peer(wsi);

	struct wsu_writereq *w, *other;

	list_for_each_entry_safe(w, other, &peer->write_q, wq) {
		do {
			int written = lws_write(wsi, w->buf + LWS_SEND_BUFFER_PRE_PADDING + w->written, w->len - w->written, LWS_WRITE_TEXT);

			if (written < 0) {
				lwsl_err("peer IO: error %d in writing\n", written);
				// TODO<lwsclose> check
				// stop reading and writing
				shutdown(lws_get_socket_fd(wsi), SHUT_RDWR);
				return -1;
			}

			w->written += (size_t)written;
		} while (w->written < w->len && !lws_partial_buffered(wsi));

		if (w->written == w->len) {
			lwsl_notice("peer IO: fin write %zu\n", w->len);
			list_del(&w->wq);
			free(w);
		}
		if (lws_partial_buffered(wsi)) {
			lwsl_notice("client IO: partial buffered, wrote %zu of %zu\n", w->written, w->len);
			lws_callback_on_writable(wsi);
			break;
		}
	}

	return 0;
}

static int wsubus_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	struct wsu_peer *peer = user;

	switch (reason) {
		// new client is connecting
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice(WSUBUS_PROTO_NAME ": client handshake...\n");
		if (0 != wsubus_filter(wsi))
			return -1;
		return 0;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice(WSUBUS_PROTO_NAME ": established\n");
		if (0 != wsu_peer_init(peer, WSUBUS_ROLE_CLIENT))
			return -1;
		break;

		// read/write
	case LWS_CALLBACK_RECEIVE:
		lwsl_notice(WSUBUS_PROTO_NAME ": protocol data received, len %lu\n", len);
		wsubus_rx(wsi, (char*)in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		lwsl_notice(WSUBUS_PROTO_NAME ": wsi %p writable now\n", wsi);
		return wsubus_tx_text(wsi);

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice(WSUBUS_PROTO_NAME ": closed\n");
		wsu_peer_deinit(wsi, peer);
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
		struct vh_context *vc = lws_protocol_vh_priv_get(
				lws_get_vhost(wsi),
				lws_get_protocol(wsi));

		if (!list_empty(&vc->origins)) {
			struct origin *origin_el, *origin_tmp;
			list_for_each_entry_safe(origin_el, origin_tmp, &vc->origins, list) {
				list_del(&origin_el->list);
				free(origin_el);
			}
		}

		break;


	case LWS_CALLBACK_CLIENT_ESTABLISHED: {
		if (0 != wsu_peer_init(peer, WSUBUS_ROLE_REMOTE))
			return -1;

		struct wsu_remote_bus *remote = &peer->u.remote;

		remote->wsi = wsi;
		memset(&remote->waiting_for, 0, sizeof remote->waiting_for);
		avl_init(&remote->stubs, avl_strcmp, false, NULL);

		remote->waiting_for.login = 1;

		json_object *adminadmin = json_object_new_object();
		json_object_object_add(adminadmin, "username", json_object_new_string("admin"));
		json_object_object_add(adminadmin, "password", json_object_new_string("admin"));

		char *d = jsonrpc__req_ubuscall(++remote->call_id, NULL, "session", "login", adminadmin);
		wsu_queue_write_str(wsi, d);

		json_object_put(adminadmin);

		return 0;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE: {
		struct wsu_remote_bus *remote = wsi_to_remote(wsi);
		struct wsu_peer *peer = wsi_to_peer(wsi);

		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj = json_tokener_parse_ex(jtok, in, len);

		struct prog_context *prog = lws_context_user(lws_get_context(remote->wsi));

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
						&& json_object_is_type(tmp, json_type_string)) {
					remote->waiting_for.login = 0;
					wsu_check_and_update_sid(peer, json_object_get_string(tmp));
				} else {
					// TODO
					lwsl_err("response to login not valid\n");
					goto out;
				}

				char *d = jsonrpc__req_ubuslisten(++remote->call_id, peer->sid, "*");
				remote->waiting_for.listen = 1;
				wsu_queue_write_str(wsi, d);
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

				char *d = jsonrpc__req_ubuslist(++remote->call_id, peer->sid, "*");
				remote->waiting_for.list_id = remote->call_id;
				wsu_queue_write_str(wsi, d);
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
					struct wsu_local_stub *cur = NULL, *last = avl_last_element(&remote->stubs, last, avl), *next;
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
							wsu_local_stub_create(remote, obj_name, obj_methods);
						} else if (!wsu_local_stub_is_same_signature(cur, obj_methods)) {
							lwsl_notice("signatures differ for %s\n", obj_name);
							// we have old version of object type / signature
							wsu_local_stub_destroy(cur);
							cur = next;
							// TODO could avoid realloc here if wsu_local_stub_create is converted to caller-allocated
							lwsl_notice("create NEW stub object for %s\n", obj_name);
							wsu_local_stub_create(remote, obj_name, obj_methods);
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
				struct wsu_proxied_call *p = NULL;
				if (
						json_object_is_type(id_jobj, json_type_int)
						&& (id = json_object_get_int(id_jobj), 1) ) {
					lwsl_notice("got response to call %d \n", id);

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

				// send status code
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

					char *d = jsonrpc__req_ubuslist(++remote->call_id, peer->sid, "*");
					remote->waiting_for.list_id = remote->call_id;
					wsu_queue_write_str(wsi, d);
				} else if (
						!strcmp("ubus.object.remove", json_object_get_string(type_jobj))
						&& json_object_object_get_ex(tmp, "path", &tmp)
						&& json_object_is_type(tmp, json_type_string)) {
					// object removed, lookup and remove
					struct wsu_local_stub *cur = avl_find_element(&remote->stubs, json_object_get_string(tmp), cur, avl);
					if (cur) {
						lwsl_notice("removing stub object for %s\n", cur->avl.key);
						wsu_local_stub_destroy(cur);
					}
				} else {
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

