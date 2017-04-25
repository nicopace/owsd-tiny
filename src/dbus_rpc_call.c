/*
 * Copyright (C) 2017 Inteno Broadband Technology AB. All rights reserved.
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
 * dbus over websocket - dbus call
 */
#include "owsd-config.h"
#include "dbus_rpc_call.h"
#include "rpc_call.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"
#include "util_dbus.h"
#include "dubus_conversions.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <dbus/dbus.h>
#include <libwebsockets.h>

#include <assert.h>
#include <sys/types.h>
#include <regex.h>

struct wsd_call_ctx {
	union {
		struct ws_request_base;
		struct ws_request_base _base;
	};

	struct ubusrpc_blob_call *args;

	struct DBusPendingCall *call_req;
};

static void wsd_call_ctx_free(void *f)
{
	struct wsd_call_ctx *ctx = f;
	free(ctx->id);

	ctx->args->destroy(&ctx->args->_base);
	blob_buf_free(&ctx->retbuf);

	free(ctx);
}

static void wsd_call_ctx_cancel_and_destroy(struct ws_request_base *base)
{
	struct wsd_call_ctx *ctx = container_of(base, struct wsd_call_ctx, _base);
	if (ctx->call_req) {
		dbus_pending_call_cancel(ctx->call_req);
		dbus_pending_call_unref(ctx->call_req);
	} else {
		wsd_call_ctx_free(ctx);
	}
}

static void wsd_call_cb(struct DBusPendingCall *call, void *data)
{
	struct wsd_call_ctx *ctx = data;
	assert(ctx->call_req == call);
	dbus_pending_call_unref(ctx->call_req);

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);

	if (!check_reply_and_make_error(reply, NULL, &ctx->retbuf)) {
		char *response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__OTHER, blobmsg_data(ctx->retbuf.head));
		wsu_queue_write_str(ctx->wsi, response_str);
		free(response_str);
		goto out;
	}

	void *tkt = blobmsg_open_array(&ctx->retbuf, dbus_message_get_signature(reply));

	DBusMessageIter iter;
	dbus_message_iter_init(reply, &iter);

	while (dbus_message_iter_get_arg_type(&iter)) {
		duconv_msg_dbus_to_ubus(&ctx->retbuf, &iter, "");
		dbus_message_iter_next(&iter);
	}

	blobmsg_close_array(&ctx->retbuf, tkt);

	char *response_str = jsonrpc__resp_ubus(ctx->id, 0, ctx->retbuf.head);
	wsu_queue_write_str(ctx->wsi, response_str);
	free(response_str);
out:
	dbus_message_unref(reply);
	ctx->call_req = NULL;
	list_del(&ctx->cq);
	ctx->cancel_and_destroy(&ctx->_base);
}

int ubusrpc_handle_dcall(struct lws *wsi, struct ubusrpc_blob *ubusrpc_, struct blob_attr *id)
{
	struct ubusrpc_blob_call *ubusrpc_blob = container_of(ubusrpc_, struct ubusrpc_blob_call, _base);
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	char *dbus_service_name = duconv_name_ubus_to_dbus_name(ubusrpc_blob->object);
	if (!dbus_service_name) {
		lwsl_err("OOM\n");
		goto out;
	}

	if (!dbus_validate_bus_name(dbus_service_name, NULL)) {
		lwsl_warn("skip invalid name \n");
		free(dbus_service_name);
		goto out;
	}

	char *dbus_object_path = duconv_name_ubus_to_dbus_path(ubusrpc_blob->object);
	lwsl_info("making DBus call s=%s o=%s m=%s\n", dbus_service_name, dbus_object_path, ubusrpc_blob->method);
	DBusMessage *msg = dbus_message_new_method_call(dbus_service_name, dbus_object_path, dbus_service_name, ubusrpc_blob->method);
	free(dbus_object_path);
	free(dbus_service_name);

	if (!msg) {
		lwsl_warn("Failed to create message\n");
		goto out;
	}

	DBusMessageIter arg_iter;
	dbus_message_iter_init_append(msg, &arg_iter);
	struct blob_attr *cur_arg;
	unsigned int rem = 0;
	blob_for_each_attr(cur_arg, ubusrpc_blob->params_buf->head, rem) {
		int dbus_type = duconv_msg_ubus_to_dbus(&arg_iter, cur_arg, NULL);
		if (dbus_type == DBUS_TYPE_INVALID) {
			lwsl_warn("Can not convert argument name=%s type=%d for DBus call %s %s\n", blobmsg_name(cur_arg), blobmsg_type(cur_arg), ubusrpc_blob->object, ubusrpc_blob->method);
			goto out2;
		}
	}

	DBusPendingCall *call;
	if (!dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, DBUS_TIMEOUT_USE_DEFAULT)) {
		goto out2;
	}

	struct wsd_call_ctx *ctx = calloc(1, sizeof *ctx);
	if (!ctx) {
		lwsl_err("OOM ctx\n");
		goto out3;
	}

	ctx->wsi = wsi;
	ctx->id = id ? blob_memdup(id) : NULL;
	ctx->cancel_and_destroy = wsd_call_ctx_cancel_and_destroy;
	ctx->call_req = call;
	ctx->args = ubusrpc_blob;
	if (id && !ctx->id) {
		lwsl_err("OOM ctx id\n");
		goto out4;
	}

	blob_buf_init(&ctx->retbuf, 0);
	dbus_message_unref(msg);

	if (!dbus_pending_call_set_notify(call, wsd_call_cb, ctx, NULL) || !call) {
		lwsl_err("failed to set notify callback\n");
		goto out5;
	}
	lwsl_debug("dbus-calling %p %p\n", call, ctx);

	struct wsu_client_session *client = wsi_to_client(wsi);
	list_add_tail(&ctx->cq, &client->rpc_call_q);

	return 0;

out5:
	free(ctx->id);
out4:
	free(ctx);
out3:
	dbus_pending_call_unref(call);
out2:
	dbus_message_unref(msg);
out:

	return -1;
}

