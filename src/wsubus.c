/*
 * ubus over websocket - client session and message handling
 */
#include "common.h"

#include "wsubus.h"
#include "wsubus.impl.h"
#include "wsubus_rpc.h"
#include "wsubus_access_check.h"

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <libwebsockets.h>

#include <errno.h>
#include <assert.h>

static callback_function wsubus_cb;

struct lws_protocols wsubus_proto = {
	"ubus-json",
	wsubus_cb,
	sizeof (struct wsubus_client_session),
	//3000 // arbitrary length
};

static bool check_origin(struct origin *origin_list, char *origin, size_t len) {

	struct origin *origin_el, *origin_tmp;

	list_for_each_entry_safe(origin_el, origin_tmp, &origin_list->list, list)
		if (!strncmp(origin_el->url, origin, len))
			return false;

	return true;
}

static int wsubus_filter(struct lws *wsi)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	int len = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) + 1;
	assert(len > 0);
	char *origin = malloc((size_t)len);

	if (!origin) {
		lwsl_err("error allocating origin header: %s\n", strerror(errno));
		return -1;
	}

	int rc = 0;
	int e;

	if (len == 0) {
		lwsl_err("no or empty origin header\n");
		rc = -2;
	} else if ((e = lws_hdr_copy(wsi, origin, len, WSI_TOKEN_ORIGIN)) < 0) {
		lwsl_err("error copying origin header %d\n", e);
		rc = -3;
	} else if (check_origin(prog->origin_list, origin, (size_t)len)) {
		lwsl_err("only localhost origin is allowed\n");
		rc = -4;
	}

	free(origin);
	return rc;
}

static int wsubus_client_init(struct wsubus_client_session *client)
{
	struct json_tokener *jtok = json_tokener_new();

	if (!jtok)
		return 1;

	static unsigned int clientid = 1; // TODO<clientid> is this good enough (never recycling ids)
	client->id = clientid++;
	client->curr_msg.len = 0;
	client->curr_msg.jtok = jtok;

	INIT_LIST_HEAD(&client->rpc_call_q);
	INIT_LIST_HEAD(&client->access_check_q);
	INIT_LIST_HEAD(&client->write_q);

	client->last_known_sid = NULL;

	return 0;
}

static void wsubus_client_msg_reset(struct wsubus_client_session *client)
{
	client->curr_msg.len = 0;

	json_tokener_reset(client->curr_msg.jtok);
}

static void wsubus_client_free(struct lws *wsi, struct wsubus_client_session *client)
{
	json_tokener_free(client->curr_msg.jtok);
	client->curr_msg.jtok = NULL;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	wsubus_unsubscribe_all_by_sid(client->last_known_sid);

	{
		struct wsubus_client_writereq *p, *n;
		list_for_each_entry_safe(p, n, &client->write_q, wq) {
			lwsl_info("free write in progress %p\n", p);
			list_del(&p->wq);
			free(p->buf);
			free(p);
		}
	}

	{
		struct wsubus_client_access_check_ctx *p, *n;
		list_for_each_entry_safe(p, n, &client->access_check_q, acq) {
			lwsl_info("free check in progress %p\n", p);
			list_del(&p->acq);
			wsubus_access_check__cancel(prog->ubus_ctx, p->req);
			if (p->destructor)
				p->destructor(p);
		}
	}


	{
		struct list_head *p, *n;
		list_for_each_safe(p, n, &client->rpc_call_q) {
			list_del(p);
			wsubus_percall_ctx_destroy_h(p);
			lwsl_info("free call in progress %p\n", p);
		}
	}

	free(client->last_known_sid);
}

static void wsubus_handle_msg(struct lws *wsi,
		struct blob_attr *blob)
{
	const struct wsubus_client_session *client = lws_wsi_user(wsi);
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
		char *json_str = jsonrpc_response_from_error(jsonrpc_req ? jsonrpc_req->id : NULL, e, NULL);
		wsubus_write_response_str(wsi, json_str);
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
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	assert(len < INT32_MAX);
	client->curr_msg.len += len;

	struct json_object *jobj = json_tokener_parse_ex(client->curr_msg.jtok, in, (int)len);

	enum json_tokener_error tok_error = json_tokener_get_error(client->curr_msg.jtok);
	int parsed_to = client->curr_msg.jtok->char_offset;

	if (!remaining_bytes_in_frame && is_final_frame) {
		if (parsed_to == (int)len && jobj && json_object_is_type(jobj, json_type_object)) {
			struct blob_buf blob = {};
			blob_buf_init(&blob, 0);
			blobmsg_add_object(&blob, jobj);
			wsubus_handle_msg(wsi, blob.head);
			blob_buf_free(&blob);
		} else {
			// parse error -> we just ignore the message
			lwsl_err("json parsing error %s, at char %d of %u, dropping msg\n",
					json_tokener_error_desc(tok_error), parsed_to, len);
			char *resp = jsonrpc_response_from_error(NULL, JSONRPC_ERRORCODE__PARSE_ERROR, NULL);
			wsubus_write_response_str(wsi, resp);
			free(resp);
		}
		wsubus_client_msg_reset(client);
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

	struct wsubus_client_session *client = lws_wsi_user(wsi);

	lwsl_info("client %zu: msg final %d, len was %zu , remaining %zu\n",
			client->id, is_final_frame, len, remaining_bytes_in_frame);
	(void)is_final_frame;

	if (len > WSUBUS_MAX_MESSAGE_LEN || remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN ||
			client->curr_msg.len + len + remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN) {
		// client intends to send too mush data, we will drop them
		lwsl_err("client %zu received fragment of frame (%zu total) making msg too long\n",
				client->id, len + remaining_bytes_in_frame);

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
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	struct wsubus_client_writereq *w, *other;

	list_for_each_entry_safe(w, other, &client->write_q, wq) {
		do {
			int written = lws_write(wsi, w->buf + LWS_SEND_BUFFER_PRE_PADDING + w->written, w->len - w->written, LWS_WRITE_TEXT);

			if (written < 0) {
				lwsl_err("client %d error %d in writing\n", client->id, written);
				// TODO<lwsclose> check
				// stop reading and writing
				shutdown(lws_get_socket_fd(wsi), SHUT_RDWR);
				return -1;
			}

			w->written += (size_t)written;
		} while (w->written < w->len && !lws_partial_buffered(wsi));

		if (w->written == w->len) {
			lwsl_notice("client %d fin write %zu\n", client->id, w->len);
			list_del(&w->wq);
			free(w->buf);
			free(w);
		} else {
			lwsl_notice("client %d partial write %zu of %zu\n", client->id, w->written, w->len);
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
	//lwsl_debug("UBUS-JSON cb called with reason %d, wsi %p, user %p, in %p len %lu\n",
			//reason, wsi, user, in, len);

	//struct prog_context *prog = lws_context_user(lws_ctx);

	// all enum reasons listed for now. Will remove unneeded when complete.
	switch (reason) {
		// proto init-destroy (maybe will put init here)
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_notice("JSONPROTO: create proto\n");
		break;
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_notice("JSONPROTO: destroy proto\n");
		break;

		// new client is connecting
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("JSONPROTO: client handshake...\n");
		if (0 != wsubus_client_init(user))
			return -1;
		if (0 != wsubus_filter(wsi)) {
			wsubus_client_free(wsi, user);
			return -1;
		}
		return 0;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("JSONPROTO: established\n");
		break;

		// read/write
	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("JSONPROTO: protocol data received, len %lu\n", len);
		wsubus_rx(wsi, (char*)in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		lwsl_notice("JSONPROTO: wsi %p writable now\n", wsi);
		return wsubus_tx_text(wsi);

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice("JSONPROTO: closed\n");
		wsubus_client_free(wsi, user);
		break;

		// debug for callbacks that should never happen
#ifndef NO_DEBUG_CALLBACKS
		// misc. Will we ever need this?
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
	case LWS_CALLBACK_GET_THREAD_ID:
	case LWS_CALLBACK_RECEIVE_PONG:
	case LWS_CALLBACK_USER:
		lwsl_err("JSONPROTO: unexpected misc callback reason %d\n", reason);
		assert (reason != reason);
		break;
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	case LWS_CALLBACK_WSI_CREATE:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
	case LWS_CALLBACK_WSI_DESTROY:
		lwsl_err("JSONPROTO: proto received net/WSI callback\n");
		assert(reason != reason);
		break;
	case LWS_CALLBACK_LOCK_POLL:
	case LWS_CALLBACK_UNLOCK_POLL:
	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_DEL_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
		lwsl_err("JSONPROTO: proto received fd callback\n");
		assert(reason != reason);
		break;
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_err("JSONPROTO: proto received http callback %d\n", reason);
		assert(reason != reason);
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		lwsl_err("JSONPROTO: proto received client callback %d\n", reason);
		assert(reason != reason);
		break;
#endif

	}
	return 0;
}

