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
 * ubus over websocket - ubus call
 */
#include "rpc_call.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "access_check.h"

#include <libubox/blobmsg.h>

#include "rpc_call_ubus.h"

#include <assert.h>

//parsing {{{
int ubusrpc_blob_call_parse_(struct ubusrpc_blob_call *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object
		[2] = { .type = BLOBMSG_TYPE_STRING }, // ubus-method
		[3] = { .type = BLOBMSG_TYPE_UNSPEC }   // ubus-params (named)
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	// we memdup the blob because params can outlive the jsonrpc blob through
	// several callbacks
	struct blob_attr *dup_blob = blob_memdup(blob);
	if (!dup_blob) {
		return -100;
	}

	struct blob_buf *params_buf = calloc(1, sizeof *params_buf);
	if (!params_buf) {
		free(dup_blob);
		return -100;
	}

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blobmsg_data for blob which
	// comes from another blob's table... here and so do we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb,
			blobmsg_data(dup_blob), (unsigned)blobmsg_len(dup_blob));

	int ret = 0;
	for (int i = 0; i < (int)__RPC_U_MAX; ++i)
		if (!tb[i])
			ret = -i-1;

	if (ret)
		goto out;

	unsigned int rem;
	struct blob_attr *cur;

#if WSD_USER_BLACKLIST_OLD
	blobmsg_for_each_attr(cur, tb[3], rem) {
		if (!strcmp("_owsd_listen", blobmsg_name(cur))) {
			ret = -1;
			goto out;
		}
	}
#endif

	blob_buf_init(params_buf, 0);

	// Copied into via foreach because tb[3] when added to doesn't work vi aubus.
	// This works but maybe we can do better without the loop (add whole params
	// table at once), but how? (tried add_field add_blob ... <blob>???
	// (blobmsg_add_blob works for id which comes from object, this comes from arr)
	blobmsg_for_each_attr(cur, tb[3], rem)
		blobmsg_add_blob(params_buf, cur);

	ubusrpc->src_blob = dup_blob;
	ubusrpc->sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->object = blobmsg_get_string(tb[1]);
	ubusrpc->method = blobmsg_get_string(tb[2]);
	ubusrpc->params_buf = params_buf;

	return 0;

out:
	free(dup_blob);
	free(params_buf);
	return ret;
}

static void ubusrpc_blob_call_destroy(struct ubusrpc_blob *ubusrpc_)
{
	struct ubusrpc_blob_call *ubusrpc = container_of(ubusrpc_, struct ubusrpc_blob_call, _base);
	blob_buf_free(ubusrpc->params_buf);
	free(ubusrpc->params_buf);
	ubusrpc_blob_destroy_default(&ubusrpc->_base);
}

struct ubusrpc_blob *ubusrpc_blob_call_parse(struct blob_attr *blob)
{
	struct ubusrpc_blob_call *ubusrpc = calloc(1, sizeof *ubusrpc);
	if (!ubusrpc)
		return NULL;

	if (ubusrpc_blob_call_parse_(ubusrpc, blob) != 0) {
		free(ubusrpc);
		return NULL;
	}

	ubusrpc->destroy = ubusrpc_blob_call_destroy;

	return &ubusrpc->_base;
}
//}}}

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	int ret = 1;

    ret = handle_call_ubus(wsi, ubusrpc_blob, id);

	return ret;
}
