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
 * ubus over websocket - client session and message handling
 */
#include "common.h"

#include "wsubus.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "access_check.h"
#include "util_jsonrpc.h"

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>

#include <libwebsockets.h>

#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <fnmatch.h>

static lws_callback_function wsubus_cb;

/** protocol + callback for RPC server */
struct lws_protocols wsubus_proto = {
	WSUBUS_PROTO_NAME,
	wsubus_cb,
	sizeof (struct wsu_peer),
	32768,    //3000 // arbitrary length
	0,    // - id
	NULL, // - user pointer
};

/*
 * WebSocket connections coming in from browser are not subject to same origin
 * policy, which means any site's JS can connect to any websocket Since we are
 * a websocket server most likely operating at a known address, we want to
 * block access to our websocket from irrelevant origins.
 *
 * Fortunately Web Browsers will include origin header in WebSocket upgrade
 * request, so we can block them using this.
 */

/**
 * \brief return true if the origin is in list of allowed origins
 */
static bool origin_allowed(struct list_head *origin_list, char *origin)
{
	struct str_list *str;

	list_for_each_entry(str, origin_list, list) {
		// According to RFC4343, DNS names are "case insensitive".
		// Further, browsers generally send domain names converted
		// to lowercase letters. Thus match origin case-insensitively.
		if (!strcasecmp(str->str, origin))
			return true;
	}

	return false;
}

/**
 * \brief return nonzero if the given wsi is allowed to upgrade to WebSocket on
 * grounds of the HTTP origin
 */
static int wsubus_filter(struct lws *wsi)
{
	int len = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN);
	assert(len >= 0);
	char *origin = malloc((size_t)len+1);

	if (!origin) {
		lwsl_err("error allocating origin header: %s\n", strerror(errno));
		return -1;
	}
	origin[len] = '\0';

	int rc = 0;
	int e;

	struct vh_context *vc;

	if (len == 0) {
		// Origin can be faked by non-browsers, and browsers always send it.
		// This means we can let in non-web agents since they may lie about origin anyway.
		rc = 0;
	} else if ((e = lws_hdr_copy(wsi, origin, len + 1, WSI_TOKEN_ORIGIN)) < 0) {
		lwsl_err("error copying origin header %d\n", e);
		rc = -3;
	} else if (!(vc = *(struct vh_context**)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi),
				lws_get_protocol(wsi)))) {
		lwsl_err("no list of origins\n");
		rc = -4;
	} else if (!origin_allowed(&vc->origins, origin)) {
		lwsl_err("origin %s not allowed\n", origin);
		rc = -5;
	}

	free(origin);
	return rc;
}

/**
 * \brief process one complete JSON RPC message (in blob) from client
 */
static void wsu_on_msg_from_client(struct lws *wsi,
		struct blob_attr *blob)
{
	const struct wsu_client_session *client = wsi_to_client(wsi);
	lwsl_info("client %u handling blobmsg buf\n", client->id);
	(void)client;

	struct jsonrpc_blob_req *jsonrpc_req = malloc(sizeof *jsonrpc_req);
	struct ubusrpc_blob *ubusrpc_req = NULL;
	int e = 0;
	if (!jsonrpc_req) {
		// free of NULL is no-op so okay
		lwsl_err("failed to alloc\n");
		e = JSONRPC_ERRORCODE__INTERNAL_ERROR;
		goto out;
	}

	// parse the JSON-RPC part of message
	if (jsonrpc_blob_req_parse(jsonrpc_req, blob) != 0) {
		lwsl_info("blobmsg not valid jsonrpc\n");
		e = JSONRPC_ERRORCODE__INVALID_REQUEST;
		goto out;
	}

	// parse the RPC method-specific arguments and other data
	ubusrpc_req = ubusrpc_blob_parse(jsonrpc_req->method, jsonrpc_req->params, &e);
	if (!ubusrpc_req) {
		lwsl_info("not valid ubus rpc in jsonrpc %d\n", e);
		goto out;
	}

	wsu_sid_update(wsi_to_peer(wsi), ubusrpc_req->sid);

	// call handler which was set by parse function
	if (ubusrpc_req->handler(wsi, ubusrpc_req, jsonrpc_req->id) != 0) {
		lwsl_info("ubusrpc method handler failed\n");
		e = JSONRPC_ERRORCODE__OTHER;
		goto out;
	}

out:
	// send jsonrpc error code if we failed...
	// otherwise handler itself is in charge of sending reply
	if (e) {
		char *json_str = jsonrpc__resp_error(jsonrpc_req ? jsonrpc_req->id : NULL, e, NULL);
		wsu_queue_write_str(wsi, json_str);
		free(json_str);
		if (ubusrpc_req) {
			if (ubusrpc_req->destroy)
				ubusrpc_req->destroy(ubusrpc_req);
			else
				ubusrpc_blob_destroy_default(ubusrpc_req);
		}
	}

	free(jsonrpc_req);
	return;
}

static void wsu_read_reset(struct wsu_peer *peer)
{
	peer->curr_msg.len = 0;

	json_tokener_reset(peer->curr_msg.jtok);
}

/**
 * \brief receive a textual message part from websocket
 */
static void wsubus_rx_json(struct lws *wsi,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = lws_remaining_packet_payload(wsi);
	int is_final_frame = lws_is_final_fragment(wsi);
	struct wsu_peer *peer = wsi_to_peer(wsi);

	assert(len < INT32_MAX);
	peer->curr_msg.len += len;

	// feed in the newly-received text into json parser
	struct json_object *jobj = json_tokener_parse_ex(peer->curr_msg.jtok, in, (int)len);

	enum json_tokener_error tok_error = json_tokener_get_error(peer->curr_msg.jtok);
	int parsed_to = peer->curr_msg.jtok->char_offset;

	if (!remaining_bytes_in_frame && is_final_frame) {
		if (parsed_to == (int)len && jobj && json_object_is_type(jobj, json_type_object)) {
			// message is finished and parser has successfully parsed everything
			struct blob_buf blob = {};
			blob_buf_init(&blob, 0);
			blobmsg_add_object(&blob, jobj);
			wsu_on_msg_from_client(wsi, blob.head);
			blob_buf_free(&blob);
		} else {
			// parse error -> we just ignore the message
			lwsl_err("json parsing error %s, at char %d of %zu, dropping msg\n",
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
		lwsl_notice(WSUBUS_PROTO_NAME ": protocol data received, len %zu\n", len);
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

	default:
		break;
	}
	return 0;
}

