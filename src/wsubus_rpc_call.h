/*
 * ubus over websocket - ubus call
 */
#pragma once

struct ubusrpc_blob_call {
	struct blob_attr *src_blob;

	const char *sid;
	const char *object;
	const char *method;
	struct blob_buf *params_buf;
};

struct lws;
struct ubusrpc_blob;
struct list_head;

void wsubus_percall_ctx_destroy_h(struct list_head *lh);

int ubusrpc_blob_call_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id);
