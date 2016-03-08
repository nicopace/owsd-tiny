/*
 * ubus over websocket - rpc parsing responses
 */
#pragma once

// TODO<deps> refactor curr_call blob_call somehow to not depend on its
// complete type here, just pointers
#include "wsubus_rpc_call.h"

#include "wsubus_rpc_sub.h"

struct jsonrpc_blob_req {
	struct blob_attr *id;
	const char *version;
	const char *method;
	struct blob_attr *params;
};

enum jsonrpc_error_code {
	JSONRPC_ERRORCODE__OK               = 0,

	JSONRPC_ERRORCODE__PARSE_ERROR      = -32700,
	JSONRPC_ERRORCODE__INVALID_REQUEST  = -32600,
	JSONRPC_ERRORCODE__METHOD_NOT_FOUND = -32601,
	JSONRPC_ERRORCODE__INVALID_PARAMS   = -32602,
	JSONRPC_ERRORCODE__INTERNAL_ERROR   = -32603,

	JSONRPC_ERRORCODE__OTHER            = -32050,
};

struct lws;

struct ubusrpc_blob {
	union {
		struct blob_attr *src_blob;
		struct ubusrpc_blob_call call;

		struct ubusrpc_blob_sub sub;
		struct ubusrpc_blob_unsub_by_id unsub_by_id;
	};
	int (*handler)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
};

int jsonrpc_blob_req_parse(struct jsonrpc_blob_req *req, const struct blob_attr *blob);

char* jsonrpc_response_from_error(struct blob_attr *id, int error_code, struct blob_attr *error_data);

char* jsonrpc_response_from_blob(struct blob_attr *id, int ubus_rc, struct blob_attr *ret_data);

enum jsonrpc_error_code ubusrpc_blob_parse(struct ubusrpc_blob *ubusrpc, const char *method, struct blob_attr *params_blob);
