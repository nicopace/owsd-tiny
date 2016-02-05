/*
 * ubus over websocket - rpc parsing responses
 */
#include "wsubus_rpc.h"

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

int jsonrpc_blob_req_parse(struct jsonrpc_blob_req *req, const struct blob_attr *blob)
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

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blob_.. for blob made with
	// blobmsg_add_object and so do we)
	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blob_data(blob), blob_len(blob));

	// set ID always, we need to return it even if error in parsing other fields
	req->id = tb[RPC_ID];
	if (!tb[RPC_JSONRPC])
		return -1;

	if (!tb[RPC_METHOD])
		return -2;

	if (!tb[RPC_PARAMS])
		return -3;

	const char *version = blobmsg_get_string(tb[RPC_JSONRPC]);
	if (strcmp("2.0", version))
		return -4;

	req->method = blobmsg_get_string(tb[RPC_METHOD]);
	req->version = version;
	req->params = tb[RPC_PARAMS];

	return 0;
}

char* jsonrpc_response_from_error(struct blob_attr *id, int error_code, struct blob_attr *error_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *obj_ticket = blobmsg_open_table(&resp_buf, "error");

	blobmsg_add_u32(&resp_buf, "code", error_code);
	blobmsg_add_string(&resp_buf, "message",
			error_code == JSONRPC_ERRORCODE__PARSE_ERROR      ? "Parse error" :
			error_code == JSONRPC_ERRORCODE__INTERNAL_ERROR   ? "Internal error" :
			error_code == JSONRPC_ERRORCODE__INVALID_REQUEST  ? "Invalid Request" :
			error_code == JSONRPC_ERRORCODE__INVALID_PARAMS   ? "Invalid params" :
			error_code == JSONRPC_ERRORCODE__METHOD_NOT_FOUND ? "Method not found" :
			"Other error");
	if (error_data && !strcmp("data", blobmsg_name(error_data)))
		blobmsg_add_blob(&resp_buf, error_data);

	blobmsg_close_table(&resp_buf, obj_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}

char* jsonrpc_response_from_blob(struct blob_attr *id,
		int ubus_rc, struct blob_attr *ret_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *array_ticket = blobmsg_open_array(&resp_buf, "result");
	blobmsg_add_u32(&resp_buf, "", ubus_rc);

	if (ret_data) {
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_TABLE, "", blobmsg_data(ret_data), blobmsg_len(ret_data));
	}

	blobmsg_close_array(&resp_buf, array_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}

enum jsonrpc_error_code ubusrpc_blob_parse(struct ubusrpc_blob *ubusrpc, const char *method, struct blob_attr *params_blob)
{
	struct {
		const char *name;
		int (*parse_func)(struct ubusrpc_blob *ubusrpc, struct blob_attr *params_blob);
		int (*handle_func)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
	} supported_methods[] = {
		{ "call", ubusrpc_blob_call_parse, ubusrpc_handle_call },
		{ "subscribe", ubusrpc_blob_sub_parse, ubusrpc_handle_sub },
	};

	for (unsigned long i = 0; i < ARRAY_SIZE(supported_methods); ++i)
		if (!strcmp(supported_methods[i].name, method)) {
			if (supported_methods[i].parse_func(ubusrpc, params_blob) == 0) {
				ubusrpc->handler = supported_methods[i].handle_func;
				return 0;
			} else {
				return JSONRPC_ERRORCODE__INVALID_PARAMS;
			}
		}

	return JSONRPC_ERRORCODE__METHOD_NOT_FOUND;
}

