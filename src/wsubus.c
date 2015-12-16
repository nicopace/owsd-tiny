#include <libwebsockets.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <errno.h>

#include "common.h"

#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

struct wsubus_client_session {
	unsigned int id;

	struct {
		struct json_tokener *jtok;
		size_t len;
	} curr_msg;

	struct libwebsocket *wsi;
	struct libwebsocket_context *lws_ctx;
};

static callback_function wsubus_cb;

struct libwebsocket_protocols wsubus_proto = {
	"ubus-json",
	wsubus_cb,
	sizeof (struct wsubus_client_session),
	//3000 // arbitrary length
};

static int wsubus_filter(struct wsubus_client_session *client)
{
	int len = lws_hdr_total_length(client->wsi, WSI_TOKEN_ORIGIN) + 1;
	char *origin = malloc(len);

	if (!origin) {
		lwsl_err("error allocating origin header: %s\n", strerror(errno));
		return -1;
	}

	int rc = 0;
	int e;
	if (len == 0) {
		lwsl_err("no or empty origin header\n");
		rc = -2;
	} else if ((e = lws_hdr_copy(client->wsi, origin, len, WSI_TOKEN_ORIGIN)) < 0) {
		lwsl_err("error copying origin header %d\n", e);
		rc = -3;
	} else if (strncmp("http://localhost/", origin, len)) { // FIXME
		// TODO configurable origin whitelist and port names also
		lwsl_err("only localost origin is allowed\n");
		rc = -4;
	}

	free(origin);
	return rc;
}

static int wsubus_client_init(struct wsubus_client_session *client,
		struct libwebsocket *wsi, struct libwebsocket_context *lws_ctx)
{
	struct json_tokener *jtok = json_tokener_new();

	if (!jtok)
		return 1;

	static unsigned int clientid; // TODO is this good enough (never recycling ids)
	client->id = clientid++;
	client->curr_msg.len = 0;
	client->curr_msg.jtok = jtok;

	client->wsi = wsi;
	client->lws_ctx = lws_ctx;

	return 0;
}

static void wsubus_client_reset(struct wsubus_client_session *client)
{
	client->curr_msg.len = 0;

	json_tokener_reset(client->curr_msg.jtok);
}

static void wsubus_client_free(struct wsubus_client_session *client)
{
	json_tokener_free(client->curr_msg.jtok);
	client->curr_msg.jtok = NULL;
}

struct ubusrpc_call {
	const char *sid;
	const char *object;
	const char *method;
	struct blob_attr *params;

	struct blob_attr *owning_blob;
};

struct jsonrpc_blob_req {
	struct blob_attr *id;
	const char *version;
	const char *method;

	// method is tag for this union
	union jsonrpc_params_ubus {
		struct ubusrpc_call call;

		/* TODO
		struct ubusrpc_sub sub;
		struct ubusrpc_unsub params_unsub;
		*/
		//struct blob_attr unparsed;
	} params;

	struct blob_attr *owning_blob;
};

int ubusrpc_call_parse_blob(struct blob_attr *blob, struct ubusrpc_call *call)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object
		[2] = { .type = BLOBMSG_TYPE_STRING }, // ubus-method
		[3] = { .type = BLOBMSG_TYPE_TABLE }   // ubus-params (named)
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	// TODO blob_(data|len) vs blobmsg_xxx usage, what is the difference and
	// which is right here? (uhttpd ubus uses blobmsg_data... here and so do
	// we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb,
			blobmsg_data(blob), blobmsg_len(blob));

	if (!tb[1])
		return -6;

	if (!tb[2])
		return -7;

	if (!tb[3])
		return -8;

	// TODO uhttpd does not allow ubus_rpc_session arg in params table, we need
	// to check it here as well...

	call->sid = blobmsg_get_string(tb[0]);
	call->object = blobmsg_get_string(tb[1]);
	call->method = blobmsg_get_string(tb[2]);
	call->params = tb[3];

	return 0;

}

int jsonrpc_blob_req_parse(struct blob_attr *blob, struct jsonrpc_blob_req *req)
{
	enum { RPC_JSONRPC, RPC_ID, RPC_METHOD, RPC_PARAMS };
	static const struct blobmsg_policy rpc_policy[] = {
		[RPC_JSONRPC] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
		[RPC_ID]      = { .name = "id",      .type = BLOBMSG_TYPE_UNSPEC },
		[RPC_METHOD]  = { .name = "method",  .type = BLOBMSG_TYPE_STRING },
		[RPC_PARAMS]  = { .name = "params",  .type = BLOBMSG_TYPE_ARRAY }
	};
	enum { __RPC_MAX = (sizeof rpc_policy / sizeof rpc_policy[0]) };

	struct blob_attr *tb[__RPC_MAX];

	// TODO blob_(data|len) vs blobmsg_xxx usage, what is the difference and
	// which is right here? (uhttpd ubus uses blob_.. for blob made with
	// blobmsg_add_object and so do we)
	blobmsg_parse(rpc_policy, __RPC_MAX, tb,
			blob_data(blob), blob_len(blob));

	if (!tb[RPC_JSONRPC])
		return -1;

	if (!tb[RPC_METHOD])
		return -2;

	if (!tb[RPC_PARAMS])
		return -3;

	const char *version = blobmsg_get_string(tb[RPC_JSONRPC]);

	if (strcmp("2.0", version))
		return -4;

	const char *method = blobmsg_get_string(tb[RPC_METHOD]);

	if (!strcmp("call", method)) {
		int rv = ubusrpc_call_parse_blob(tb[RPC_PARAMS], &req->params.call);
		if (rv)
			return -100 + rv;
	//} else if (!strcmp("subscribe", method)){ TODO
	//} else if (!strcmp("unsubscribe", method)){ TODO
	} else {
		return -100;
	}

	req->id = tb[RPC_ID] ? blob_data(tb[RPC_ID]) : NULL;
	req->method = method;
	req->version = version;

	return 0;
}

#if 0
static int wsubus_check_json(struct json_object *msg)
{
	if (!json_object_is_type(msg, json_type_object))
		return -1;

	struct json_object *jsonrpc_ver_jstr;
	struct json_object *id_j;
	struct json_object *method_jstr;
	struct json_object *params_jarr;

	if (!json_object_object_get_ex(msg, "jsonrpc", &jsonrpc_ver_jstr) ||
			!json_object_object_get_ex(msg, "id", &id_j) ||
			!json_object_object_get_ex(msg, "method", &method_jstr) ||
			!json_object_object_get_ex(msg, "params", &params_jarr))
		return -3;

	if (strcmp("2.0", json_object_get_string(jsonrpc_ver_jstr)))
		return -4;

	if (json_object_array_length(params_jarr) != 4) // sid, object, method, params
		return -5;


	struct json_object *u_sid_jstr;
	struct json_object *u_object_jstr;
	struct json_object *u_method_jstr;
	struct json_object *u_args_obj;

	if (!(u_sid_jstr = json_object_array_get_idx(params_jarr, 0)) ||
			!(u_object_jstr = json_object_array_get_idx(params_jarr, 1)) ||
			!(u_method_jstr = json_object_array_get_idx(params_jarr, 2)) ||
			!(u_args_obj = json_object_array_get_idx(params_jarr, 3)))
		return -6;

	if (!json_object_is_type(u_sid_jstr, json_type_string) ||
			!json_object_is_type(u_object_jstr, json_type_string) ||
			!json_object_is_type(u_method_jstr, json_type_string) ||
			!json_object_is_type(u_args_obj, json_type_object))
		return -7;

	return 0;
}
#endif

void wsubus_ret_handler(struct ubus_request *req,
		int type,
	   	struct blob_attr *msg)
{
	lwsl_debug("ubus invoke handled: %p %d %p\n", req, type, msg);

	struct wsubus_client_session *client = req->priv;

	unsigned int rem;
	struct blob_attr *pos;
	blobmsg_for_each_attr(pos, msg, rem) 
		lwsl_debug("-- %s , %s \n", blobmsg_name(pos),
			   	blobmsg_type(pos) == BLOBMSG_TYPE_STRING ? "\"\"" : 
			   	blobmsg_type(pos) == BLOBMSG_TYPE_TABLE ? "{}" : 
			   	blobmsg_type(pos) == BLOBMSG_TYPE_ARRAY ? "[]" : 
				"<>");
	lwsl_debug("---- \n");

	char *json_str = blobmsg_format_json(msg, true);
	if (!json_str) {
		lwsl_err("json format of ubus response failed\n");
		return;
	}
	size_t json_len = strlen(json_str);

	lwsl_debug("reply was: %.*s ...\n", 50, json_str);

	assert(json_len < WSUBUS_MAX_MESSAGE_LEN);

	unsigned char *buf = malloc(LWS_SEND_BUFFER_PRE_PADDING
			+ json_len 
			+ LWS_SEND_BUFFER_POST_PADDING);
	if (!buf) {
		lwsl_err("failed to alloc ubus response buf");
		free(json_str);
		return;
	}

	memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, json_str, json_len);
	free(json_str);

	int written = libwebsocket_write(client->wsi, buf+LWS_SEND_BUFFER_PRE_PADDING, json_len,
			LWS_WRITE_TEXT);

	if (written != (int)json_len) {
		lwsl_err("Partial write is not handled yet\n");
	}

	free(buf);
	return;

	libwebsocket_callback_on_writable(client->lws_ctx, client->wsi);
}

static void wsubus_handle_msg(struct wsubus_client_session *client,
		struct blob_attr *blob)
{
	lwsl_info("client %u handling blobmsg buf\n", client->id);

	struct prog_context *prog = libwebsocket_context_user(client->lws_ctx);

	struct jsonrpc_blob_req req;

	if (jsonrpc_blob_req_parse(blob, &req) != 0) {
		lwsl_info("blobmsg not valid jsonrpc\n");
		return;
	}

	if (strcmp(req.method, "call")) {
		lwsl_info("method != call\n");
		return;
	}

	lwsl_info("json is valid ubus-rpc: do ubus %s   %s %s with sid %s\n",
			req.method,
			req.params.call.object, req.params.call.method,
			req.params.call.sid);

	struct blob_buf *ureq = calloc(1, sizeof *ureq);
	blob_buf_init(ureq, 0);

	unsigned int rem;
	struct blob_attr *pos;

	// TODO this works but maybe we can do better without the loop (add whole params
	// table at once), don't know how (tried add_field add_blob ...
	blobmsg_for_each_attr(pos, req.params.call.params, rem)
		blobmsg_add_blob(ureq, pos); //*/

	uint32_t object_id;
	int ret = ubus_lookup_id(prog->ubus_ctx, req.params.call.object, &object_id);

	if (ret != UBUS_STATUS_OK) {
		lwsl_info("lookup failed: %s\n", ubus_strerror(ret));
		goto out;
	}

	ret = ubus_invoke(prog->ubus_ctx, object_id, req.params.call.method,
			ureq->head, wsubus_ret_handler, client, 1000);

	if (ret != UBUS_STATUS_OK) {
		lwsl_info("invoke failed: %s\n", ubus_strerror(ret));
		goto out;
	}

	// TODO do ubus here

out:
	blob_buf_free(ureq);
	free(ureq);
}

static void wsubus_rx_json(struct wsubus_client_session *client,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = libwebsockets_remaining_packet_payload(client->wsi);
	int is_final_frame = libwebsocket_is_final_fragment(client->wsi);

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
			wsubus_handle_msg(client, blob.head);
			blob_buf_free(&blob);
		} else {
			// parse error -> we just ignore the message
			lwsl_err("json parsing error %s, at char %d of %u, dropping msg\n",
					json_tokener_error_desc(tok_error), parsed_to, len);
		}
		wsubus_client_reset(client);
	} else {
		if (tok_error != json_tokener_continue) {
			// parse error mid-message, client will send more data
			// For now we drop the client, but we could mark state and skip only this message
			lwsl_err("unexpected json parsing error %s\n", json_tokener_error_desc(tok_error));
			lwsl_err("Dropping client\n");

			// TODO check
			// stop reading and writing
			shutdown(libwebsocket_get_socket_fd(client->wsi), SHUT_RDWR);
		}
	}

	if (jobj)
		json_object_put(jobj);
}

static void wsubus_rx_blob(struct wsubus_client_session *client,
		const char *in,
		size_t len)
{
	// TODO implement
	// for now we will drop client which sends binary message
	lwsl_err("Binary (blobmsg) not implemented\n");
	// for now just do nothing with binary message
}

static void wsubus_rx(struct wsubus_client_session *client,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = libwebsockets_remaining_packet_payload(client->wsi);
	int is_final_frame = libwebsocket_is_final_fragment(client->wsi);

	lwsl_info("client %zu: msg final %d, len was %zu , remaining %zu\n",
			client->id, is_final_frame, len, remaining_bytes_in_frame);

	if (len > WSUBUS_MAX_MESSAGE_LEN || remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN ||
			client->curr_msg.len + len + remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN) {
		// client intends to send too mush data, we will drop them
		lwsl_err("client %zu received fragment of frame (%zu total) making msg too long\n",
				client->id, len + remaining_bytes_in_frame);

		// TODO check
		// stop reading from mad client
		shutdown(libwebsocket_get_socket_fd(client->wsi), SHUT_RD);
	}

	if (lws_frame_is_binary(client->wsi)) {
		wsubus_rx_blob(client, in, len);
	} else {
		wsubus_rx_json(client, in, len);
	}
}

static int wsubus_cb(struct libwebsocket_context *lws_ctx,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	//lwsl_debug("UBUS-JSON cb called with reason %d, wsi %p, user %p, in %p len %lu\n",
			//reason, wsi, user, in, len);

	//struct prog_context *prog = libwebsocket_context_user(lws_ctx);

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
		return wsubus_client_init(user, wsi, lws_ctx)
			|| wsubus_filter(user);

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("JSONPROTO: established\n");
		break;

		// read/write
	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("JSONPROTO: protocol data received, len %lu\n", len);
		wsubus_rx(user, (char*)in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		lwsl_notice("JSONPROTO: wsi %p writable now\n", wsi);
		break;

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice("JSONPROTO: closed\n");
		wsubus_client_free(user);
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

