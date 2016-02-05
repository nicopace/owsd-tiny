/*
 * ubus over websocket - ubus event subscription
 */
#pragma once

// TODO maybe these will be same type
struct ubusrpc_blob_sub {
	struct blob_attr *src_blob;

	const char *objname;
};


struct ubusrpc_blob_unsub {
};


struct ubusrpc_blob;

int ubusrpc_blob_sub_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

struct lws;

int ubusrpc_handle_sub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
