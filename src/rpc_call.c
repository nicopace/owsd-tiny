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
#include <libubus.h>

#include <assert.h>

int ubusrpc_blob_call_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object
		[2] = { .type = BLOBMSG_TYPE_STRING }, // ubus-method
		[3] = { .type = BLOBMSG_TYPE_TABLE }   // ubus-params (named)
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

	// does not allow ubus_rpc_session arg in params, as we will add it
	unsigned int rem;
	struct blob_attr *cur;
	blobmsg_for_each_attr(cur, tb[3], rem) {
		if (!strcmp("ubus_rpc_session", blobmsg_name(cur)))
			ret = -5;
		if (!strcmp("_owsd_listen", blobmsg_name(cur)))
			ret = -5;
	}

	if (ret) {
		free(dup_blob);
		free(params_buf);
		return ret;
	}

	blob_buf_init(params_buf, 0);

	// Copied into via foreach because tb[3] when added to doesn't work vi aubus.
	// This works but maybe we can do better without the loop (add whole params
	// table at once), but how? (tried add_field add_blob ... <blob>???
	// (blobmsg_add_blob works for id which comes from object, this comes from arr)
	blobmsg_for_each_attr(cur, tb[3], rem)
		blobmsg_add_blob(params_buf, cur);

	ubusrpc->call.src_blob = dup_blob;
	ubusrpc->call.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->call.object = blobmsg_get_string(tb[1]);
	ubusrpc->call.method = blobmsg_get_string(tb[2]);
	ubusrpc->call.params_buf = params_buf;

	return 0;
}

struct wsubus_percall_ctx {
	enum {
		WSUBUS_CALL_STATE_PREP,
		WSUBUS_CALL_STATE_CHECK,
		WSUBUS_CALL_STATE_CALL_PRE,
		WSUBUS_CALL_STATE_CALL,
	} state;

	struct lws *wsi;

	struct blob_attr *id;
	struct ubusrpc_blob_call *call_args;
	struct blob_attr *retdata;

	struct ubus_request *invoke_req;

	struct wsubus_client_access_check_ctx access_check;

	struct list_head cq;
};

static struct wsubus_percall_ctx *wsubus_percall_ctx_create(
		struct lws *wsi,
		struct blob_attr *id,
		struct ubusrpc_blob_call *call_args)
{
	struct wsubus_percall_ctx *ret = malloc(sizeof *ret);

	ret->wsi = wsi;

	ret->id = blob_memdup(id);
	ret->call_args = call_args;
	ret->retdata = NULL;

	ret->invoke_req = NULL;

	ret->access_check.req = NULL;

	return ret;
}

static void wsubus_percall_ctx_destroy(struct wsubus_percall_ctx *call_ctx)
{
	free(call_ctx->id);

	free(call_ctx->call_args->src_blob);
	blob_buf_free(call_ctx->call_args->params_buf);
	free(call_ctx->call_args->params_buf);

	free(call_ctx->call_args);

	free(call_ctx->retdata);

	if (call_ctx->invoke_req) {
		struct prog_context *prog = lws_context_user(lws_get_context(call_ctx->wsi));
		assert(call_ctx->state == WSUBUS_CALL_STATE_CALL);
		ubus_abort_request(prog->ubus_ctx, call_ctx->invoke_req);
		free(call_ctx->invoke_req);
	}

	free(call_ctx);
}

void wsubus_percall_ctx_destroy_h(struct list_head *lh)
{
	wsubus_percall_ctx_destroy(list_entry(lh, struct wsubus_percall_ctx, cq));
}

static int wsubus_call_do_check_then_do_call(struct wsubus_percall_ctx *curr_call);
static void wsubus_access_on_completed(struct wsubus_access_check_req *req, void *ctx, bool allow);
static int wsubus_call_do(struct wsubus_percall_ctx *curr_call);
static void wsubus_call_on_completed(struct ubus_request *req, int status);
static void wsubus_call_on_retdata(struct ubus_request *req, int type, struct blob_attr *msg);

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	struct ubusrpc_blob_call *ubusrpc_req = &ubusrpc_blob->call;
	struct wsu_client_session *client = wsi_to_client(wsi);

	int ret;

	lwsl_info("have valid ubus-rpc: do ubus call  %s %s with sid %s\n",
			ubusrpc_req->object, ubusrpc_req->method, ubusrpc_req->sid);

	struct wsubus_percall_ctx *curr_call = NULL;

	if(!list_empty(&client->rpc_call_q)) {
		lwsl_info("another request in progress \n");
	}

	curr_call = wsubus_percall_ctx_create(wsi, id, ubusrpc_req);
	curr_call->state = WSUBUS_CALL_STATE_PREP;

	list_add_tail(&curr_call->cq, &client->rpc_call_q);
	ret = wsubus_call_do_check_then_do_call(curr_call);

	if (ret != UBUS_STATUS_OK) {
		// we hide the real error with access check
		ret = UBUS_STATUS_PERMISSION_DENIED;

		list_del(&curr_call->cq);
		wsubus_percall_ctx_destroy(curr_call);

		// invoke never happened, we need to send ubus error status
		// (jsonrpc success, but ubus code != 0)
		char *response = jsonrpc__resp_ubus(id, ret, NULL);
		wsu_queue_write_str(wsi, response);
		free(response);
	}

	return 0; // means json-rpc went okay, we sent ubus error or rasponse here or in callback
}

static int wsubus_call_do_check_then_do_call(struct wsubus_percall_ctx *curr_call)
{
	struct prog_context *prog = lws_context_user(lws_get_context(curr_call->wsi));
	struct wsu_client_session *client = wsi_to_client(curr_call->wsi);

	assert(curr_call->state == WSUBUS_CALL_STATE_PREP);

	int ret = UBUS_STATUS_OK;
	curr_call->access_check.destructor = NULL; // XXX

	list_add_tail(&curr_call->access_check.acq, &client->access_check_q);

	curr_call->access_check.req = wsubus_access_check__call(prog->ubus_ctx, curr_call->call_args->object, curr_call->call_args->method, curr_call->call_args->sid, curr_call, wsubus_access_on_completed);

	if (!curr_call->access_check.req) {
		lwsl_warn("access check error\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;

		list_del(&curr_call->access_check.acq);
		if (curr_call->access_check.destructor)
			curr_call->access_check.destructor(&curr_call->access_check);
		goto out;
	}

	curr_call->state = WSUBUS_CALL_STATE_CHECK;

out:
	return ret;
}

static void wsubus_access_on_completed(struct wsubus_access_check_req *req, void *ctx, bool allow)
{
	struct wsubus_percall_ctx *curr_call = ctx;
	lwsl_debug("ubus access check %p completed: allow = %d\n", req, allow);

	assert(curr_call->state == WSUBUS_CALL_STATE_CHECK);
	assert(curr_call->access_check.req == req);

	curr_call->access_check.req = NULL;
	list_del(&curr_call->access_check.acq);

	int ret = UBUS_STATUS_OK;

	if (!allow) {
		ret = UBUS_STATUS_PERMISSION_DENIED;
		goto out;
	}

	curr_call->state = WSUBUS_CALL_STATE_CALL_PRE;

	ret = wsubus_call_do(curr_call);

out:
	if (ret != UBUS_STATUS_OK) {
		// hide all error codes in access behind permission denied
		ret = UBUS_STATUS_PERMISSION_DENIED;
		char *json_str = jsonrpc__resp_ubus(curr_call->id, ret, NULL);
		wsu_queue_write_str(curr_call->wsi, json_str);
		free(json_str);

		list_del(&curr_call->cq);
		wsubus_percall_ctx_destroy(curr_call);
	}
}

static int wsubus_call_do(struct wsubus_percall_ctx *curr_call)
{
	struct prog_context *prog = lws_context_user(lws_get_context(curr_call->wsi));
	int ret;

	assert(curr_call->state == WSUBUS_CALL_STATE_CALL_PRE);

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

	blobmsg_add_string(curr_call->call_args->params_buf, "ubus_rpc_session", curr_call->call_args->sid);

	if (!strcmp(curr_call->call_args->sid, UBUS_DEFAULT_SID)) {
		struct vh_context *vc = lws_protocol_vh_priv_get(lws_get_vhost(curr_call->wsi), lws_get_protocol(curr_call->wsi));
		blobmsg_add_string(curr_call->call_args->params_buf, "_owsd_listen", vc->name);
	}

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
	curr_call->state = WSUBUS_CALL_STATE_CALL;

	ubus_complete_request_async(prog->ubus_ctx, curr_call->invoke_req);

out:
	return ret;
}

static void wsubus_call_on_completed(struct ubus_request *req, int status)
{
	lwsl_debug("ubus call %p completed: %d\n", req, status);

	struct wsubus_percall_ctx *curr_call = req->priv;

	assert(curr_call->state == WSUBUS_CALL_STATE_CALL);
	assert(curr_call->invoke_req == req);

	// is req->status_code or status (the arg) what we want?
	if (req->status_code != status)
		lwsl_warn("status != req->status_code (%d != %d)\n", status, req->status_code);

	// retdata is deep copied pointer from retdata handler 
	char *json_str = jsonrpc__resp_ubus(curr_call->id, status, curr_call->retdata);

	wsu_queue_write_str(curr_call->wsi, json_str);
	free(json_str);
	free(req);
	curr_call->invoke_req = NULL;

	list_del(&curr_call->cq);
	wsubus_percall_ctx_destroy(curr_call);
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

	assert(curr_call->state == WSUBUS_CALL_STATE_CALL);
	assert(!curr_call->retdata);

	curr_call->retdata = blob_memdup(msg);
}
