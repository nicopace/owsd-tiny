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
#pragma once
#include "rpc_list.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"
#include "ubusx_acl.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubus.h>

#include <libwebsockets.h>

#include <assert.h>

static void ubus_lookup_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *user)
{
	(void)ctx;

	lwsl_info("looked up %s\n", obj->path);
	if (!ubusx_acl__allow_object(obj->path /* object name */))
		return;
	struct ws_request_base *req = user;

	void *objs_tkt = blobmsg_open_table(&req->retbuf, obj->path);

	if (!obj->signature) {
		goto out;
	}

	unsigned int r_methods;
	struct blob_attr *cur_method;

	blob_for_each_attr(cur_method, obj->signature, r_methods) {
		if (!ubusx_acl__allow_method(obj->path /* object name */,
				blobmsg_name(cur_method) /* method name */))
			continue;
		void *methods_tkt = blobmsg_open_table(&req->retbuf, blobmsg_name(cur_method));

		struct blob_attr *cur_arg;
		unsigned r_args = (unsigned)blobmsg_len(cur_method);
		__blob_for_each_attr(cur_arg, blobmsg_data(cur_method), r_args) {
			if (blobmsg_type(cur_arg) != BLOBMSG_TYPE_INT32)
				continue;
			const char *typestr = blobmsg_type_to_str(blobmsg_get_u32(cur_arg));
			typestr = typestr ? typestr : "unknown";
			blobmsg_add_string(&req->retbuf, blobmsg_name(cur_arg), typestr);
		}

		blobmsg_close_table(&req->retbuf, methods_tkt);
	}
out:
	blobmsg_close_table(&req->retbuf, objs_tkt);
}

static int handle_list_ubus(struct ws_request_base *req, struct lws *wsi, struct ubusrpc_blob *ubusrpc_, struct blob_attr *id, bool output)
{
	struct ubusrpc_blob_list *ubusrpc = container_of(ubusrpc_, struct ubusrpc_blob_list, _base);
	char *response_str;
	int ret = 0;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	lwsl_info("about to lookup %s\n", ubusrpc->pattern);
	ret = ubus_lookup(prog->ubus_ctx, ubusrpc->pattern, ubus_lookup_cb, req);

	if (output) {
		if (ret) {
			response_str = jsonrpc__resp_ubus(id, ret ? ret : -1, NULL);
		} else {
			// using blobmsg_data here to pass only array part of blobmsg
			response_str = jsonrpc__resp_ubus(id, 0, req->retbuf.head);
		}

		wsu_queue_write_str(wsi, response_str);

		// free memory
		free(response_str);
	}

	return 0;
}

