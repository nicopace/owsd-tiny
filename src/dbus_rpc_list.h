#pragma once

struct ubusrpc_blob;
struct blob_attr;
struct lws;

int ubusrpc_handle_dlist(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
