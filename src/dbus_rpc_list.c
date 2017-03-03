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
 * dbus over websocket - dbus list
 */
#include "dbus_rpc_list.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <dbus/dbus.h>

#include <libwebsockets.h>

#include <assert.h>

struct wsd_call_ctx {
	struct lws *wsi;

	struct blob_attr *id;
	struct ubusrpc_blob_list *list_args;
	struct blob_buf retbuf;

	struct DBusPendingCall *call_req;

	struct list_head cq;
};

static void wsd_list_cb(DBusPendingCall *call, void *data)
{
	lwsl_err("DBUS LIST REPLY %p\n", call);
	struct wsd_call_ctx *ctx = data;
	blob_buf_init(&ctx->retbuf, 0);
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);
	char *response_str;
	int type = dbus_message_get_type(reply);
	if (type == DBUS_MESSAGE_TYPE_ERROR) {
		void *data_tkt = blobmsg_open_table(&ctx->retbuf, "data");
		blobmsg_add_string(&ctx->retbuf, "DBus", dbus_message_get_error_name(reply));
		blobmsg_close_table(&ctx->retbuf, data_tkt);
		response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__INTERNAL_ERROR, blobmsg_data(ctx->retbuf.head));
		goto out;
	}
	if (type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__INTERNAL_ERROR, NULL);
		goto out;
	}

	if (strcmp(dbus_message_get_signature(reply), "as")) {
		lwsl_err("DBUS LIST NAME ERR ARR :%s", dbus_message_get_signature(reply));
		void *data_tkt = blobmsg_open_table(&ctx->retbuf, "data");
		blobmsg_add_string(&ctx->retbuf, "DBus", DBUS_ERROR_INVALID_SIGNATURE);
		blobmsg_close_table(&ctx->retbuf, data_tkt);
		response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__INTERNAL_ERROR, blobmsg_data(ctx->retbuf.head));
		goto out;
	}

	DBusMessageIter resp_iter, arr_iter;
	dbus_message_iter_init(reply, &resp_iter);

	dbus_message_iter_recurse(&resp_iter, &arr_iter);
	void *results_ticket = blobmsg_open_table(&ctx->retbuf, "");
	while (dbus_message_iter_get_arg_type(&arr_iter) != DBUS_MESSAGE_TYPE_INVALID) {
		const char *str;
		dbus_message_iter_get_basic(&arr_iter, &str);
		lwsl_err("DBUS LIST NAME %s\n", str);
		blobmsg_add_string(&ctx->retbuf, str, "{}");
		dbus_message_iter_next(&arr_iter);
	}
	blobmsg_close_table(&ctx->retbuf, results_ticket);

	response_str = blobmsg_format_json(ctx->retbuf.head, true);

out:
	dbus_pending_call_unref(call);
	dbus_message_unref(reply);
	blob_buf_free(&ctx->retbuf);

	wsu_queue_write_str(ctx->wsi, response_str);

	// free memory
	free(response_str);
}

static void wsd_call_ctx_free(void *f)
{
	struct wsd_call_ctx *ctx = f;
	free(ctx->list_args->src_blob);
	free(ctx->list_args);
	free(ctx->id);
	free(ctx);
}

int ubusrpc_handle_dlist(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct wsd_call_ctx *ctx = calloc(1, sizeof *ctx);
	ctx->wsi = wsi;
	ctx->list_args = &ubusrpc->list;
	ctx->id = id ? blob_memdup(id) : NULL;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	lwsl_info("about to DBUS lookup %s\n", ubusrpc->list.pattern);
	DBusMessage *msg = dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames");
	DBusPendingCall *call;
	dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, 2000);
	dbus_pending_call_set_notify(call, wsd_list_cb, ctx, wsd_call_ctx_free);

	dbus_message_unref(msg);

	return 0;
}

