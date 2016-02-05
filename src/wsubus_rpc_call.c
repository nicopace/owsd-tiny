/*
 * ubus over websocket - ubus call
 */
#include "wsubus_rpc_call.h"

#include "common.h"
#include "wsubus.impl.h"
#include "wsubus_rpc.h"

#include <libubox/blobmsg.h>
#include <libubus.h>

// TODO<deps> refactor should maybe drop this big include if all lws-specific
// is put in wsubus.impl.h, and when client context is refactored (so we have
// it passed around, not wsi). We would have to add own debug logging then.
#include <libwebsockets.h>

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
			blobmsg_data(dup_blob), blobmsg_len(dup_blob));

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
	ubusrpc->call.sid = tb[0] ? blobmsg_get_string(tb[0]) : "00000000000000000000000000000000";
	ubusrpc->call.object = blobmsg_get_string(tb[1]);
	ubusrpc->call.method = blobmsg_get_string(tb[2]);
	ubusrpc->call.params_buf = params_buf;

	return 0;
}

static int wsubus_call_do_check_then_do_call(struct lws *wsi);
static void wsubus_access_on_completed(struct ubus_request *req, int status);
static int wsubus_call_do(struct lws *wsi);
static void wsubus_call_on_completed(struct ubus_request *req, int status);
static void wsubus_call_on_retdata(struct ubus_request *req, int type, struct blob_attr *msg);

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	struct ubusrpc_blob_call *ubusrpc_req = &ubusrpc_blob->call;
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	int ret;

	lwsl_info("have valid ubus-rpc: do ubus call  %s %s with sid %s\n",
			ubusrpc_req->object, ubusrpc_req->method, ubusrpc_req->sid);

	// TODO for multiple concurrrent requests per client, use queue here...
	if(client->curr_call.state != WSUBUS_CALL_STATE_READY) {
		lwsl_info("another request in progress (state %d)\n", client->curr_call.state);
		assert(client->curr_call.invoke_req != NULL);
		// TODO Here we will send jsonrpc ok with ubus error code. We could also say jsonrpc error maybe
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto respond_with_ubus_error;
	}

	client->curr_call.id = blob_memdup(id);
	client->curr_call.call_args = ubusrpc_req;
	client->curr_call.state = WSUBUS_CALL_STATE_CHECK_PRE;

	ret = wsubus_call_do_check_then_do_call(wsi);
	if (ret != UBUS_STATUS_OK) {
		// we hide the real error with access check
		ret = UBUS_STATUS_PERMISSION_DENIED;
		goto respond_with_ubus_error;
	}

respond_with_ubus_error:
	if (ret != UBUS_STATUS_OK) {
		// invoke never happened, we need to send ubus error status
		// (jsonrpc success, but ubus code != 0)
		char *response = jsonrpc_response_from_blob(id, ret, NULL);
		wsubus_write_response_str(wsi, response);
		free(response);

		wsubus_client_call_reset(client);
	}

	return 0; // means json-rpc went okay, we sent ubus error or rasponse here or in callback
}

int ubusrpc_handle_call_nochecks(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	struct ubusrpc_blob_call *ubusrpc_req = &ubusrpc_blob->call;
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	int ret;

	lwsl_info("have valid ubus-rpc: do ubus call  %s %s with sid %s\n",
			ubusrpc_req->object, ubusrpc_req->method, ubusrpc_req->sid);

	// TODO for multiple concurrrent requests per client, use queue here...
	if(client->curr_call.state != WSUBUS_CALL_STATE_READY) {
		lwsl_info("another request in progress (state %d)\n", client->curr_call.state);
		// TODO Here we will send jsonrpc ok with ubus error code. We could also say jsonrpc error maybe
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto respond_with_ubus_error;
	}

	uint32_t object_id;
	ret = ubus_lookup_id(prog->ubus_ctx, ubusrpc_req->object, &object_id);

	if (ret != UBUS_STATUS_OK) {
		lwsl_info("lookup failed: %s\n", ubus_strerror(ret));
		goto respond_with_ubus_error;
	}

	struct ubus_request *invoke_req = calloc(1, sizeof *invoke_req);
	if (!invoke_req) {
		lwsl_err("alloc ubus call req failed\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto respond_with_ubus_error;
	}

	lwsl_info("ubus call request %p...\n", invoke_req);
	ret = ubus_invoke_async(prog->ubus_ctx, object_id, ubusrpc_req->method, ubusrpc_req->params_buf->head, invoke_req);

	if (ret != UBUS_STATUS_OK) {
		lwsl_info("invoke failed: %s\n", ubus_strerror(ret));
		// req will not free itself since will not complete so we dispose it
		free(invoke_req);
		// free the req's fields
		free(ubusrpc_req->src_blob);
		free(ubusrpc_req->params_buf);
		goto respond_with_ubus_error;
	}

	invoke_req->priv = wsi;
	invoke_req->data_cb = wsubus_call_on_retdata;
	invoke_req->complete_cb = wsubus_call_on_completed;
	client->curr_call.invoke_req = invoke_req;
	client->curr_call.id = blob_memdup(id);
	client->curr_call.call_args = ubusrpc_req;
	client->curr_call.state = WSUBUS_CALL_STATE_CALL;

	ubus_complete_request_async(prog->ubus_ctx, invoke_req);

respond_with_ubus_error:
	if (ret != UBUS_STATUS_OK) {
		// invoke never happened, we need to send ubus error status
		// (jsonrpc success, but ubus code != 0)
		char *response = jsonrpc_response_from_blob(id, ret, NULL);
		wsubus_write_response_str(wsi, response);
		free(response);
	}

	return 0; // means json-rpc went okay, we sent ubus error or rasponse here or in callback
}

static int wsubus_call_do_check_then_do_call(struct lws *wsi)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	int ret;
	uint32_t access_id;

	assert(client->curr_call.state == WSUBUS_CALL_STATE_CHECK_PRE);

	struct ubus_request *access_req = calloc(1, sizeof *access_req);
	struct blob_buf *blob_for_access = calloc(1, sizeof *blob_for_access);
	if (!access_req || !blob_for_access) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	ret = ubus_lookup_id(prog->ubus_ctx, "session", &access_id);
	if (ret != UBUS_STATUS_OK) {
		lwsl_err("lookup for session failed: %s\n", ubus_strerror(ret));
		free(access_req);
		goto out;
	}

	blob_buf_init(blob_for_access, 0);

	blobmsg_add_string(blob_for_access, "ubus_rpc_session", client->curr_call.call_args->sid);
	blobmsg_add_string(blob_for_access, "object", client->curr_call.call_args->object);
	blobmsg_add_string(blob_for_access, "function", client->curr_call.call_args->method);

	lwsl_info("ubus access request %p...\n", access_req);
	ret = ubus_invoke_async(prog->ubus_ctx, access_id, "access", blob_for_access->head, access_req);

	if (ret != UBUS_STATUS_OK) {
		lwsl_warn("access check invoke failed: %s", ubus_strerror(ret));
		// free req since it won't be completed
		free(access_req);
		goto out;
	}

	access_req->priv = wsi;
	access_req->data_cb = wsubus_call_on_retdata;
	access_req->complete_cb = wsubus_access_on_completed;
	client->curr_call.invoke_req = access_req;
	client->curr_call.state = WSUBUS_CALL_STATE_CHECK;

	ubus_complete_request_async(prog->ubus_ctx, access_req);

out:
	blob_buf_free(blob_for_access);
	free(blob_for_access);
	return ret;
}

static void wsubus_access_on_completed(struct ubus_request *req, int status)
{
	lwsl_debug("ubus access check %p completed: %d\n", req, status);

	struct lws *wsi = req->priv;
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	assert(client->curr_call.state == WSUBUS_CALL_STATE_CHECK);
	assert(client->curr_call.invoke_req == req);

	// is req->status_code or status (the arg) what we want?
	if (req->status_code != status)
		lwsl_warn("status != req->status_code (%d != %d)\n", status, req->status_code);

	int ret = UBUS_STATUS_OK;

	if (status != UBUS_STATUS_OK) {
		ret = status;
		goto out;
	}
	if (!client->curr_call.retdata) {
		ret = UBUS_STATUS_NO_DATA;
		goto out;
	}

	unsigned rem;
	struct blob_attr *cur;
	bool found = false;
	blobmsg_for_each_attr(cur, client->curr_call.retdata, rem) {
		if (!strcmp("access", blobmsg_name(cur)) && blobmsg_type(cur) == BLOBMSG_TYPE_BOOL) {
			bool access = blobmsg_get_bool(cur);
			found = true;
			lwsl_info("access var in result is %hhd \n", access);
			if (access == false) {
				ret = UBUS_STATUS_PERMISSION_DENIED;
				goto out;
			}
			break;
		}
	}

	if (!found) {
		ret = UBUS_STATUS_NOT_FOUND;
		goto out;
	}

	// manually free state that call uses
	free(client->curr_call.retdata);
	client->curr_call.retdata = NULL;
	client->curr_call.invoke_req = NULL;
	client->curr_call.state = WSUBUS_CALL_STATE_CALL_PRE;

	ret = wsubus_call_do(wsi);

out:
	if (ret != UBUS_STATUS_OK) {
		// hide all error codes in access behind permission denied
		ret = UBUS_STATUS_PERMISSION_DENIED;
		char *json_str = jsonrpc_response_from_blob(client->curr_call.id, ret, NULL);
		wsubus_write_response_str(wsi, json_str);
		free(json_str);

		wsubus_client_call_reset(client);
	}

	free(req);
}

static int wsubus_call_do(struct lws *wsi)
{
	struct wsubus_client_session *client = lws_wsi_user(wsi);
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	int ret;

	assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL_PRE);

	uint32_t object_id;
	ret = ubus_lookup_id(prog->ubus_ctx, client->curr_call.call_args->object, &object_id);
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

	blobmsg_add_string(client->curr_call.call_args->params_buf, "ubus_rpc_session", client->curr_call.call_args->sid);

	lwsl_info("ubus call request %p...\n", call_req);
	ret = ubus_invoke_async(prog->ubus_ctx, object_id, client->curr_call.call_args->method, client->curr_call.call_args->params_buf->head, call_req);
	if (ret != UBUS_STATUS_OK) {
		lwsl_info("invoke failed: %s\n", ubus_strerror(ret));
		// req will not free itself since will not complete so we dispose it
		free(call_req);
		goto out;
	}

	call_req->priv = wsi;
	call_req->data_cb = wsubus_call_on_retdata;
	call_req->complete_cb = wsubus_call_on_completed;
	client->curr_call.invoke_req = call_req;
	client->curr_call.state = WSUBUS_CALL_STATE_CALL;

	ubus_complete_request_async(prog->ubus_ctx, client->curr_call.invoke_req);

out:
	return ret;
}

static void wsubus_call_on_completed(struct ubus_request *req, int status)
{
	lwsl_debug("ubus call %p completed: %d\n", req, status);

	struct lws *wsi = req->priv;
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL);
	assert(client->curr_call.invoke_req == req);

	// is req->status_code or status (the arg) what we want?
	if (req->status_code != status)
		lwsl_warn("status != req->status_code (%d != %d)\n", status, req->status_code);

	// retdata is deep copied pointer from retdata handler 
	char *json_str = jsonrpc_response_from_blob(client->curr_call.id, status, client->curr_call.retdata);

	wsubus_write_response_str(wsi, json_str);
	wsubus_client_call_reset(client);

	free(json_str);
	free(req);
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

	struct wsubus_client_session *client = lws_wsi_user(req->priv);

	assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL || client->curr_call.state == WSUBUS_CALL_STATE_CHECK);

	client->curr_call.retdata = blob_memdup(msg);
}
