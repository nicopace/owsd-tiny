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
 * ubus over websocket - rpc parsing responses
 */
#include "rpc.h"
#include "util_jsonrpc.h"

// FIXME RPCs should add themselves to list via macro / constructor magic,
// instead of explicitly listing them to add them in list of supported RPCs
#include "rpc_call.h"
#include "rpc_list.h"
#include "rpc_sub.h"

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

void ubusrpc_blob_destroy_default(struct ubusrpc_blob *ubusrpc_)
{
	free(ubusrpc_->src_blob);
	free(ubusrpc_);
}

struct ubusrpc_blob* ubusrpc_blob_parse(const char *method, struct blob_attr *params_blob, enum jsonrpc_error_code *err)
{
	struct {
		const char *name;
		struct ubusrpc_blob* (*parse_func)(struct blob_attr *params_blob);
		int (*handle_func)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
	} supported_methods[] = {
		{ "call", ubusrpc_blob_call_parse, ubusrpc_handle_call },
		{ "list", ubusrpc_blob_list_parse, ubusrpc_handle_list },
		{ "subscribe", ubusrpc_blob_sub_parse, ubusrpc_handle_sub },
		{ "subscribe-list", ubusrpc_blob_sub_list_parse, ubusrpc_handle_sub_list },
		{ "unsubscribe", ubusrpc_blob_sub_parse, ubusrpc_handle_unsub }, // parse is same as sub since args same
	};
	enum jsonrpc_error_code e;
	struct ubusrpc_blob *ret;
	for (unsigned long i = 0; i < ARRAY_SIZE(supported_methods); ++i)
		if (!strcmp(supported_methods[i].name, method)) {
			ret = supported_methods[i].parse_func(params_blob);
			if (ret) {
				e = JSONRPC_ERRORCODE__OK;
				ret->handler = supported_methods[i].handle_func;
			} else {
				e = JSONRPC_ERRORCODE__INVALID_PARAMS;
			}
			goto out;
		}

	e = JSONRPC_ERRORCODE__METHOD_NOT_FOUND;
	ret = NULL;

out:
	if (err)
		*err = e;
	return ret;
}
