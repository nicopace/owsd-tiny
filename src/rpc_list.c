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
 * ubus over websocket - ubus list
 */
#include "rpc_list.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubus.h>

#include <libwebsockets.h>

#include <assert.h>

int ubusrpc_blob_list_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	if (blob_id(blob) != BLOBMSG_TYPE_ARRAY) {
		ubusrpc->list.src_blob = NULL;
		ubusrpc->list.pattern = NULL;
		return 0;
	}

	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_UNSPEC }, // session ID, IGNORED to keep compat
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object pattern
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	struct blob_attr *dup_blob = blob_memdup(blob);
	if (!dup_blob) {
		return -100;
	}

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blobmsg_data for blob which
	// comes from another blob's table... here and so do we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb, blobmsg_data(dup_blob), (unsigned)blobmsg_len(dup_blob));

	if (!tb[1])
		return -2;

	ubusrpc->list.src_blob = dup_blob;
	ubusrpc->call.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->list.pattern = blobmsg_get_string(tb[1]);

	return 0;
}

struct list_cb_data {
	int error;
	struct blob_buf buf;
};

static void ubus_lookup_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *user)
{
	(void)ctx;

	lwsl_info("looked up %s\n", obj->path);
	struct list_cb_data *data = user;

	void *objs_tkt = blobmsg_open_table(&data->buf, obj->path);

	if (!obj->signature) {
		goto out;
	}

	unsigned int r_methods;
	struct blob_attr *cur_method;

	blob_for_each_attr(cur_method, obj->signature, r_methods) {
		void *methods_tkt = blobmsg_open_table(&data->buf, blobmsg_name(cur_method));

		struct blob_attr *cur_arg;
		unsigned r_args = (unsigned)blobmsg_len(cur_method);
		__blob_for_each_attr(cur_arg, blobmsg_data(cur_method), r_args) {
			if (blobmsg_type(cur_arg) != BLOBMSG_TYPE_INT32)
				continue;
			const char *typestr = blobmsg_type_to_str(blobmsg_get_u32(cur_arg));
			typestr = typestr ? typestr : "unknown";
			blobmsg_add_string(&data->buf, blobmsg_name(cur_arg), typestr);
		}

		blobmsg_close_table(&data->buf, methods_tkt);
	}
out:
	blobmsg_close_table(&data->buf, objs_tkt);
}

int ubusrpc_handle_list(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	char *response_str;
	int ret = 0;

	struct list_cb_data list_data = {1, {}};
	blob_buf_init(&list_data.buf, 0);

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	void *results_ticket = blobmsg_open_table(&list_data.buf, "");
	lwsl_info("about to lookup %s\n", ubusrpc->list.pattern);
	ret = ubus_lookup(prog->ubus_ctx, ubusrpc->list.pattern, ubus_lookup_cb, &list_data);
	lwsl_info("after loookup rc %d, error %d\n", ret, list_data.error);
	blobmsg_close_table(&list_data.buf, results_ticket);

	if (ret) {
		response_str = jsonrpc__resp_ubus(id, ret ? ret : -1, NULL);
	} else {
		// using blobmsg_data here to pass only array part of blobmsg
		response_str = jsonrpc__resp_ubus(id, 0, blobmsg_data(list_data.buf.head));
	}

	blob_buf_free(&list_data.buf);

	wsu_queue_write_str(wsi, response_str);

	// free memory
	free(response_str);
	free(ubusrpc->list.src_blob);
	free(ubusrpc);
	return 0;
}

