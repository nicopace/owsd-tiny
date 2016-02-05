/*
 * ubus over websocket - ubus call
 */
#pragma once

struct wsubus_context_call {
	enum {
		WSUBUS_CALL_STATE_READY = 0,
		WSUBUS_CALL_STATE_CHECK_PRE,
		WSUBUS_CALL_STATE_CHECK,
		WSUBUS_CALL_STATE_CALL_PRE,
		WSUBUS_CALL_STATE_CALL,
	} state;

	struct blob_attr *id;
	struct ubusrpc_blob_call *call_args;
	struct blob_attr *retdata;

	struct ubus_request *invoke_req;
};

struct ubusrpc_blob_call {
	struct blob_attr *src_blob;

	const char *sid;
	const char *object;
	const char *method;
	struct blob_buf *params_buf;
};

struct ubusrpc_blob;

int ubusrpc_blob_call_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

struct lws;

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id);
