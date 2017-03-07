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
	struct DBusMessageIter arr_iter;

	struct DBusMessage *reply;
	int reply_slot;

	struct DBusPendingCall *call_req;

	struct list_head cq;
};

static void wsd_introspect_cb(DBusPendingCall *call, void *data);

static void introspect_list_next(struct wsd_call_ctx *ctx)
{
	struct prog_context *prog = lws_context_user(lws_get_context(ctx->wsi));
	const char *str;
	dbus_message_iter_get_basic(&ctx->arr_iter, &str);
	DBusMessage *introspect = dbus_message_new_method_call(str, "/org/freedesktop", DBUS_INTERFACE_INTROSPECTABLE, "Introspect");
	DBusPendingCall *introspect_call;
	dbus_connection_send_with_reply(prog->dbus_ctx, introspect, &introspect_call, -1);
	dbus_pending_call_set_notify(introspect_call, wsd_introspect_cb, ctx, NULL);
	dbus_message_unref(introspect);
	dbus_pending_call_unref(introspect_call);
}

static void introspect_list_finish(struct wsd_call_ctx *ctx)
{
	char *response_str = jsonrpc__resp_ubus(ctx->id, 0, ctx->retbuf.head);
	//char *response_str = blobmsg_format_json(ctx->retbuf.head, true);
	wsu_queue_write_str(ctx->wsi, response_str);
	free(response_str);
	dbus_message_unref(ctx->reply);
}

static void wsd_introspect_cb(DBusPendingCall *call, void *data)
{
	lwsl_err("INTROSPECTED ###### %p\n", call);
	struct wsd_call_ctx *ctx = data;

	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	const char *str;
	dbus_message_iter_get_basic(&ctx->arr_iter, &str);
	lwsl_err("(%s)\n", str);

	void *p = blobmsg_open_table(&ctx->retbuf, str);
	blobmsg_add_u32(&ctx->retbuf, "serial", dbus_message_get_serial(reply));
	blobmsg_add_u32(&ctx->retbuf, "type", dbus_message_get_type(reply));
	blobmsg_add_string(&ctx->retbuf, "signature", dbus_message_get_signature(reply));

	dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &str);
	blobmsg_add_string(&ctx->retbuf, "value", str);

	blobmsg_close_table(&ctx->retbuf, p);

	if (dbus_message_iter_next(&ctx->arr_iter)) {
		introspect_list_next(ctx);
	} else {
		introspect_list_finish(ctx);
	}

	dbus_message_unref(reply);
}


static void wsd_call_ctx_free(void *f)
{
	lwsl_err("FREEING LIST MSG\n");
	struct wsd_call_ctx *ctx = f;
	blob_buf_free(&ctx->retbuf);
	free(ctx->list_args->src_blob);
	free(ctx->list_args);
	free(ctx->id);
	dbus_message_free_data_slot(&ctx->reply_slot);
	free(ctx);
}

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

	ctx->reply = reply;
	//dbus_message_ref(ctx->reply);
	ctx->reply_slot = -1;
	dbus_message_allocate_data_slot(&ctx->reply_slot);
	dbus_message_set_data(ctx->reply, ctx->reply_slot, ctx, wsd_call_ctx_free);
	DBusMessageIter resp_iter;
	dbus_message_iter_init(reply, &resp_iter);

	dbus_message_iter_recurse(&resp_iter, &ctx->arr_iter);

	if (dbus_message_iter_get_arg_type(&ctx->arr_iter) != DBUS_TYPE_INVALID) {
		introspect_list_next(ctx);
	} else {
		introspect_list_finish(ctx);
	}

	return;

out:
	wsu_queue_write_str(ctx->wsi, response_str);
}

int ubusrpc_handle_dlist(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct wsd_call_ctx *ctx = calloc(1, sizeof *ctx);
	ctx->wsi = wsi;
	ctx->list_args = &ubusrpc->list;
	ctx->id = id ? blob_memdup(id) : NULL;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	lwsl_info("about to DBUS lookup %s\n", ubusrpc->list.pattern);
	DBusMessage *msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "ListNames");
	if (!msg) {
		goto out;
	}

	DBusPendingCall *call;
	if (!dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, 2000) || !call) {
		dbus_message_unref(msg);
		goto out;
	}
	if (!dbus_pending_call_set_notify(call, wsd_list_cb, ctx, NULL)) {
		dbus_message_unref(msg);
		goto out;
	}

	dbus_message_unref(msg);
	dbus_pending_call_unref(call);

	return 0;

out:
	// free ctx since it we werent able to pass it to notify handler
	wsd_call_ctx_free(ctx);
	return -1;
}

