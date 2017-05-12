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
#pragma once

#include "rpc_call.h"
#include "wsubus.impl.h"
#include "access_check.h"
#include "common.h"

#include <libubus.h>

// per-request context {{{
struct wsubus_percall_ctx {
	union {
		struct ws_request_base;
		struct ws_request_base _base;
	};

	struct ubusrpc_blob_call *call_args;
	struct ubus_request *invoke_req;
	struct wsubus_client_access_check_ctx access_check;
};

static void wsubus_percall_ctx_destroy(struct ws_request_base *base)
{
	struct wsubus_percall_ctx *call_ctx = container_of(base, struct wsubus_percall_ctx, _base);
	free(call_ctx->id);

	call_ctx->call_args->destroy(&call_ctx->call_args->_base);
	blob_buf_free(&call_ctx->retbuf);

	if (call_ctx->invoke_req) {
		struct prog_context *prog = lws_context_user(lws_get_context(call_ctx->wsi));
		ubus_abort_request(prog->ubus_ctx, call_ctx->invoke_req);
		free(call_ctx->invoke_req);
	}

	free(call_ctx);
}

static struct wsubus_percall_ctx *wsubus_percall_ctx_create(
		struct lws *wsi,
		struct blob_attr *id,
		struct ubusrpc_blob_call *call_args)
{
	struct wsubus_percall_ctx *ret = malloc(sizeof *ret);

	ret->wsi = wsi;
	ret->id = id ? blob_memdup(id): NULL;
	memset(&ret->retbuf, 0, sizeof ret->retbuf);
	blobmsg_buf_init(&ret->retbuf);
	ret->cancel_and_destroy = wsubus_percall_ctx_destroy;

	ret->call_args = call_args;
	ret->invoke_req = NULL;
	ret->access_check.req = NULL;

	return ret;
}
//}}}


static void wsubus_call_on_completed(struct ubus_request *req, int status)
{
	lwsl_debug("ubus call %p completed: %d\n", req, status);

	struct wsubus_percall_ctx *curr_call = req->priv;

	assert(curr_call->invoke_req == req);

	// is req->status_code or status (the arg) what we want?
	if (req->status_code != status)
		lwsl_warn("status != req->status_code (%d != %d)\n", status, req->status_code);

	char *json_str = jsonrpc__resp_ubus(curr_call->id, status, blobmsg_len(curr_call->retbuf.head) ? blobmsg_data(curr_call->retbuf.head) : NULL);

	wsu_queue_write_str(curr_call->wsi, json_str);
	free(json_str);
	free(req);
	curr_call->invoke_req = NULL;

	list_del(&curr_call->cq);
	wsubus_percall_ctx_destroy(&curr_call->_base);
}

static void wsubus_call_on_retdata(struct ubus_request *req, int type, struct blob_attr *msg)
{
	lwsl_debug("ubus invoke %p returned: %s\n", req,
			type == BLOBMSG_TYPE_STRING ? "\"\"" :
			type == BLOBMSG_TYPE_TABLE ? "{}" :
			type == BLOBMSG_TYPE_ARRAY ? "[]" : "<>");
	unsigned int rem;
	struct blob_attr *pos;
	blobmsg_for_each_attr(pos, msg, rem)
		lwsl_debug("-- %s , %s \n", blobmsg_name(pos),
				blobmsg_type(pos) == BLOBMSG_TYPE_STRING ? "\"\"" :
				blobmsg_type(pos) == BLOBMSG_TYPE_TABLE ? "{}" :
				blobmsg_type(pos) == BLOBMSG_TYPE_ARRAY ? "[]" : "<>");
	lwsl_debug("---- \n");

	struct wsubus_percall_ctx *curr_call = req->priv;

	blobmsg_add_field(&curr_call->retbuf, blobmsg_type(msg), "", blobmsg_data(msg), blobmsg_data_len(msg));
}

static int wsubus_call_do_call(struct wsubus_percall_ctx *curr_call)
{
	struct prog_context *prog = lws_context_user(lws_get_context(curr_call->wsi));
	int ret;

	uint32_t object_id;
	ret = ubus_lookup_id(prog->ubus_ctx, curr_call->call_args->object, &object_id);
	if (ret != UBUS_STATUS_OK) {
		lwsl_info("lookup failed: %s\n", ubus_strerror(ret));
		goto out;
	}

	struct ubus_request *call_req = calloc(1, sizeof *call_req);
	if (!call_req) {
		lwsl_err("alloc ubus call req failed\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

#if WSD_USER_BLACKLIST_OLD
	if (!strcmp(curr_call->call_args->sid, UBUS_DEFAULT_SID)) {
		struct vh_context *vc = *(struct vh_context**)lws_protocol_vh_priv_get(lws_get_vhost(curr_call->wsi), lws_get_protocol(curr_call->wsi));
		blobmsg_add_string(curr_call->call_args->params_buf, "_owsd_listen", vc->name);
	}
#endif

	lwsl_info("ubus call request %p...\n", call_req);
	ret = ubus_invoke_async(prog->ubus_ctx, object_id, curr_call->call_args->method, curr_call->call_args->params_buf->head, call_req);
	if (ret != UBUS_STATUS_OK) {
		lwsl_info("invoke failed: %s\n", ubus_strerror(ret));
		// req will not free itself since will not complete so we dispose it
		free(call_req);
		goto out;
	}

	call_req->priv = curr_call;
	call_req->data_cb = wsubus_call_on_retdata;
	call_req->complete_cb = wsubus_call_on_completed;
	curr_call->invoke_req = call_req;

	ubus_complete_request_async(prog->ubus_ctx, curr_call->invoke_req);

out:
	return ret;
}


static void wsubus_access_on_completed(struct wsubus_access_check_req *req, void *ctx, bool allow)
{
	struct wsubus_percall_ctx *curr_call = ctx;
	lwsl_debug("ubus access check %p completed: allow = %d\n", req, allow);

	assert(curr_call->access_check.req == req);

	wsubus_access_check_free(curr_call->access_check.req);
	curr_call->access_check.req = NULL;
	list_del(&curr_call->access_check.acq);

	int ret = UBUS_STATUS_OK;

	if (!allow) {
		ret = UBUS_STATUS_PERMISSION_DENIED;
		goto out;
	}

	ret = wsubus_call_do_call(curr_call);

out:
	if (ret != UBUS_STATUS_OK) {
		// hide all error codes in access behind permission denied
		ret = UBUS_STATUS_PERMISSION_DENIED;
		char *json_str = jsonrpc__resp_ubus(curr_call->id, ret, NULL);
		wsu_queue_write_str(curr_call->wsi, json_str);
		free(json_str);

		list_del(&curr_call->cq);
		wsubus_percall_ctx_destroy(&curr_call->_base);
	}
}

static int wsubus_call_do_check_then_do_call(struct wsubus_percall_ctx *curr_call)
{
	struct wsu_client_session *client = wsi_to_client(curr_call->wsi);

	int ret = 0;
	curr_call->access_check.destructor = NULL; // XXX

	list_add_tail(&curr_call->access_check.acq, &client->access_check_q);

	if ((curr_call->access_check.req = wsubus_access_check_new()))
		ret = wsubus_access_check__call(curr_call->access_check.req, curr_call->wsi, curr_call->call_args->sid, curr_call->call_args->object, curr_call->call_args->method, curr_call->call_args->params_buf, curr_call, wsubus_access_on_completed);

	if (!curr_call->access_check.req || ret) {
		lwsl_warn("access check error\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;

		list_del(&curr_call->access_check.acq);
		if (curr_call->access_check.destructor)
			curr_call->access_check.destructor(&curr_call->access_check);

		wsubus_access_check_free(curr_call->access_check.req);

		goto out;
	}

out:
	return ret;
}

int handle_call_ubus(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	struct ubusrpc_blob_call *ubusrpc_req = container_of(ubusrpc_blob, struct ubusrpc_blob_call, _base);
	struct wsu_client_session *client = wsi_to_client(wsi);

	int ret;

	lwsl_info("have valid ubus-rpc: do ubus call  %s %s with sid %s\n",
			ubusrpc_req->object, ubusrpc_req->method, ubusrpc_req->sid);

	struct wsubus_percall_ctx *curr_call = NULL;

	if(!list_empty(&client->rpc_call_q)) {
		lwsl_info("another request in progress \n");
	}

	curr_call = wsubus_percall_ctx_create(wsi, id, ubusrpc_req);

	list_add_tail(&curr_call->cq, &client->rpc_call_q);
	ret = wsubus_call_do_check_then_do_call(curr_call);

	if (ret != UBUS_STATUS_OK) {
		// we hide the real error with access check
		ret = UBUS_STATUS_PERMISSION_DENIED;

		list_del(&curr_call->cq);
		wsubus_percall_ctx_destroy(&curr_call->_base);

		// invoke never happened, we need to send ubus error status
		// (jsonrpc success, but ubus code != 0)
		char *response = jsonrpc__resp_ubus(id, ret, NULL);
		wsu_queue_write_str(wsi, response);
		free(response);
	}

	return 0; // means json-rpc went okay, we sent ubus error or rasponse here or in callback
}
