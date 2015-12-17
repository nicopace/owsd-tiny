#include <libwebsockets.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <errno.h>
#include <assert.h>

#include "common.h"

#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

struct wsubus_client_session {
	unsigned int id;

	struct {
		struct json_tokener *jtok;
		size_t len;
	} curr_msg;

	struct {
		enum {
			WSUBUS_CALL_STATE_READY = 0,
			WSUBUS_CALL_STATE_CHECK_PRE,
			WSUBUS_CALL_STATE_CHECK,
			WSUBUS_CALL_STATE_CALL_PRE,
			WSUBUS_CALL_STATE_CALL,
		} state;

		struct blob_attr *id;
		struct ubusrpc_blob_call *call_args;
		struct blob_attr *retdata;

		struct ubus_request *invoke_req;
	} curr_call;
};

static callback_function wsubus_cb;

struct lws_protocols wsubus_proto = {
	"ubus-json",
	wsubus_cb,
	sizeof (struct wsubus_client_session),
	//3000 // arbitrary length
};

static int wsubus_filter(struct lws *wsi)
{
	int len = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) + 1;
	char *origin = malloc(len);

	if (!origin) {
		lwsl_err("error allocating origin header: %s\n", strerror(errno));
		return -1;
	}

	int rc = 0;
	int e;
	if (len == 0) {
		lwsl_err("no or empty origin header\n");
		rc = -2;
	} else if ((e = lws_hdr_copy(wsi, origin, len, WSI_TOKEN_ORIGIN)) < 0) {
		lwsl_err("error copying origin header %d\n", e);
		rc = -3;
	} else if (strncmp("http://localhost/", origin, len)) { // FIXME
		// TODO configurable origin whitelist and port names also
		lwsl_err("only localost origin is allowed\n");
		rc = -4;
	}

	free(origin);
	return rc;
}

static int wsubus_client_init(struct wsubus_client_session *client)
{
	struct json_tokener *jtok = json_tokener_new();

	if (!jtok)
		return 1;

	static unsigned int clientid; // TODO is this good enough (never recycling ids)
	client->id = clientid++;
	client->curr_msg.len = 0;
	client->curr_msg.jtok = jtok;

	memset(&client->curr_call, 0, sizeof client->curr_call);

	return 0;
}

static void wsubus_client_msg_reset(struct wsubus_client_session *client)
{
	client->curr_msg.len = 0;

	json_tokener_reset(client->curr_msg.jtok);
}

static void wsubus_client_free(struct lws *wsi, struct wsubus_client_session *client)
{
	json_tokener_free(client->curr_msg.jtok);
	client->curr_msg.jtok = NULL;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	if (client->curr_call.invoke_req) {
		assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL || client->curr_call.state == WSUBUS_CALL_STATE_CHECK);
		ubus_abort_request(prog->ubus_ctx, client->curr_call.invoke_req);
		free(client->curr_call.invoke_req);
		client->curr_call.invoke_req = NULL;
	}
	free(client->curr_call.id);
	client->curr_call.id = NULL;
	free(client->curr_call.retdata);
	client->curr_call.retdata = NULL;
}

int wsubus_write_response_str(struct lws *wsi,
		const char *response_str)
{
	if (!response_str) {
		lwsl_err("Not writing null message\n");
		return -1;
	}

	size_t len = strlen(response_str);

	assert(len < WSUBUS_MAX_MESSAGE_LEN);

	lwsl_debug("sending reply: %.*s ...\n", len > 50 ? 50 : len, response_str);

	unsigned char *buf = malloc(LWS_SEND_BUFFER_PRE_PADDING
			+ len
			+ LWS_SEND_BUFFER_POST_PADDING);
	if (!buf) {
		lwsl_err("failed to alloc ubus response buf");
		return -2;
	}

	memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, response_str, len);

	int written = lws_write(wsi, buf+LWS_SEND_BUFFER_PRE_PADDING, len,
			LWS_WRITE_TEXT);

	while (written != (int)len) {
		lwsl_debug("Partial write, repeating\n");
		written += lws_write(wsi,
				buf+LWS_SEND_BUFFER_PRE_PADDING+written, len-written,
				LWS_WRITE_TEXT);
	}

	free(buf);
	return 0;

	lws_callback_on_writable(wsi);
}

struct jsonrpc_blob_req {
	struct blob_attr *id;
	const char *version;
	const char *method;
	struct blob_attr *params;

	struct blob_attr *owning_blob;
};

enum jsonrpc_error_code {
	JSONRPC_ERRORCODE__PARSE_ERROR      = -32700,
	JSONRPC_ERRORCODE__INVALID_REQUEST  = -32600,
	JSONRPC_ERRORCODE__METHOD_NOT_FOUND = -32601,
	JSONRPC_ERRORCODE__INVALID_PARAMS   = -32602,
	JSONRPC_ERRORCODE__INTERNAL_ERROR   = -32603,

	JSONRPC_ERRORCODE__OTHER            = -32050,
};

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

	// TODO blob_(data|len) vs blobmsg_xxx usage, what is the difference and
	// which is right here? (uhttpd ubus uses blob_.. for blob made with
	// blobmsg_add_object and so do we)
	blobmsg_parse(rpc_policy, __RPC_MAX, tb,
			blob_data(blob), blob_len(blob));

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
static char* jsonrpc_response_error(struct blob_attr *id, int error_code, struct blob_attr *error_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *obj_ticket = blobmsg_open_table(&resp_buf, "error");

	blobmsg_add_u32(&resp_buf, "code", error_code);
	blobmsg_add_string(&resp_buf, "message",
			error_code == JSONRPC_ERRORCODE__PARSE_ERROR      ? "Parse error" :
			error_code == JSONRPC_ERRORCODE__INTERNAL_ERROR   ? "Internal error" :
			error_code == JSONRPC_ERRORCODE__INVALID_REQUEST  ? "Invalid Request" :
			error_code == JSONRPC_ERRORCODE__INVALID_PARAMS   ? "Invalid params" :
			error_code == JSONRPC_ERRORCODE__METHOD_NOT_FOUND ? "Method not found" :
			"Other error");
	if (error_data && !strcmp("data", blobmsg_name(error_data)))
		blobmsg_add_blob(&resp_buf, error_data);

	blobmsg_close_table(&resp_buf, obj_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}


static char* jsonrpc_response_from_blob(struct blob_attr *id,
		int ubus_rc, struct blob_attr *ret_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *array_ticket = blobmsg_open_array(&resp_buf, "result");
	blobmsg_add_u32(&resp_buf, "", ubus_rc);

	if (ret_data) {
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_TABLE, "", blobmsg_data(ret_data), blobmsg_len(ret_data));
	}

	blobmsg_close_array(&resp_buf, array_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}

struct ubusrpc_blob {
	union {
		struct blob_attr *src_blob;
		struct ubusrpc_blob_call {
			struct blob_attr *src_blob;

			const char *sid;
			const char *object;
			const char *method;
			struct blob_buf *params_buf;
		} call;

		/* TODO
		struct ubusrpc_sub sub;
		struct ubusrpc_unsub params_unsub;
		*/
	};
	int (*handler)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
};

static int ubusrpc_blob_call_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object
		[2] = { .type = BLOBMSG_TYPE_STRING }, // ubus-method
		[3] = { .type = BLOBMSG_TYPE_TABLE }   // ubus-params (named)
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	struct blob_attr *dup_blob = blob_memdup(blob);
	if (!dup_blob) {
		return -100;
	}

	struct blob_buf *params_buf = calloc(1, sizeof *params_buf);
	if (!params_buf) {
		free(dup_blob);
		return -100;
	}

	// TODO blob_(data|len) vs blobmsg_xxx usage, what is the difference and
	// which is right here? (uhttpd ubus uses blobmsg_data... here and so do
	// we)
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

	// Copied into separate blob_buf because tb[3] when added to ubus doesn't work.
	// This works but maybe we can do better without the loop (add whole params
	// table at once), but how? (tried add_field add_blob ... <addblob>???
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

static void wsubus_client_call_reset(struct wsubus_client_session *client)
{
	free(client->curr_call.retdata);
	client->curr_call.retdata = NULL;

	free(client->curr_call.id);
	client->curr_call.id = NULL;

	free(client->curr_call.call_args->src_blob);
	client->curr_call.call_args->src_blob = NULL;

	blob_buf_free(client->curr_call.call_args->params_buf);
	free(client->curr_call.call_args->params_buf);
	client->curr_call.call_args->params_buf = NULL;

	free(client->curr_call.call_args);
	client->curr_call.call_args = NULL;

	// we don't free these, the requests free themselves
	if (client->curr_call.invoke_req) {
		assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL || client->curr_call.state == WSUBUS_CALL_STATE_CHECK);
		client->curr_call.invoke_req = NULL;
	}
	client->curr_call.state = WSUBUS_CALL_STATE_READY;
}

void wsubus_call_on_retdata(struct ubus_request *req,
		int type,
	   	struct blob_attr *msg)
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

void wsubus_call_on_completed(struct ubus_request *req, int status)
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

int wsubus_call_do(struct lws *wsi)
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

void wsubus_access_on_completed(struct ubus_request *req, int status)
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
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	unsigned rem;
	struct blob_attr *cur;
	blobmsg_for_each_attr(cur, client->curr_call.retdata, rem) {
		if (!strcmp("access", blobmsg_name(cur)) && blobmsg_type(cur) == BLOBMSG_TYPE_BOOL) {
			lwsl_info("access var in result is %hhd \n", access);
			if (blobmsg_get_bool(cur) == false) {
				ret = UBUS_STATUS_PERMISSION_DENIED;
				goto out;
			}
			break;
		}
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
	}

	return 0;
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
	client->curr_call.state = WSUBUS_CALL_STATE_CALL_PRE;

	ubus_complete_request_async(prog->ubus_ctx, invoke_req);

respond_with_ubus_error:
	if (ret != UBUS_STATUS_OK) {
		// invoke never happened, we need to send ubus error status
		// (jsonrpc success, but ubus code != 0)
		char *response = jsonrpc_response_from_blob(id, ret, NULL);
		wsubus_write_response_str(wsi, response);
		free(response);
	}

	return 0;
}

enum jsonrpc_error_code ubusrpc_blob_parse(struct ubusrpc_blob *ubusrpc, const char *method, struct blob_attr *params_blob)
{
	struct {
		const char *name;
		int (*parse_func)(struct ubusrpc_blob *ubusrpc, struct blob_attr *params_blob);
		int (*handle_func)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
	} supported_methods[] = {
		{ "call", ubusrpc_blob_call_parse, ubusrpc_handle_call },
	};

	for (unsigned long i = 0; i < ARRAY_SIZE(supported_methods); ++i)
		if (!strcmp(supported_methods[i].name, method)) {
			if (supported_methods[i].parse_func(ubusrpc, params_blob) == 0) {
				ubusrpc->handler = supported_methods[i].handle_func;
				return 0;
			} else {
				return JSONRPC_ERRORCODE__INVALID_PARAMS;
			}
		}

	return JSONRPC_ERRORCODE__METHOD_NOT_FOUND;
}


static void wsubus_handle_msg(struct lws *wsi,
		struct blob_attr *blob)
{
	const struct wsubus_client_session *client = lws_wsi_user(wsi);
	lwsl_info("client %u handling blobmsg buf\n", client->id);

	struct jsonrpc_blob_req *jsonrpc_req = malloc(sizeof *jsonrpc_req);
	struct ubusrpc_blob *ubusrpc_req = malloc(sizeof *ubusrpc_req);

	int e = 0;
	if (!jsonrpc_req || !ubusrpc_req) {
		// free of NULL is no-op so okay
		lwsl_err("failed to alloc\n");
		e = JSONRPC_ERRORCODE__INTERNAL_ERROR;
		goto out;
	}

	if (jsonrpc_blob_req_parse(jsonrpc_req, blob) != 0) {
		lwsl_info("blobmsg not valid jsonrpc\n");
		e = JSONRPC_ERRORCODE__INVALID_REQUEST;
		goto out;
	}

	if ((e = ubusrpc_blob_parse(ubusrpc_req, jsonrpc_req->method, jsonrpc_req->params)) != 0) {
		lwsl_info("not valid ubus rpc in jsonrpc %d\n", e);
		goto out;
	}

	if (ubusrpc_req->handler(wsi, ubusrpc_req, jsonrpc_req->id) != 0) {
		lwsl_info("ubusrpc method handler failed\n");
		e = JSONRPC_ERRORCODE__OTHER;
		goto out;
	}

out:
	// send jsonrpc error code if we failed...
	if (e) {
		char *json_str = jsonrpc_response_error(jsonrpc_req ? jsonrpc_req->id : NULL, e, NULL);
		wsubus_write_response_str(wsi, json_str);
		free(json_str);
		free(ubusrpc_req);
	}

	free(jsonrpc_req);
	return;
}

static void wsubus_rx_json(struct lws *wsi,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = lws_remaining_packet_payload(wsi);
	int is_final_frame = lws_is_final_fragment(wsi);
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	assert(len < INT32_MAX);
	client->curr_msg.len += len;

	struct json_object *jobj = json_tokener_parse_ex(client->curr_msg.jtok, in, (int)len);

	enum json_tokener_error tok_error = json_tokener_get_error(client->curr_msg.jtok);
	int parsed_to = client->curr_msg.jtok->char_offset;

	if (!remaining_bytes_in_frame && is_final_frame) {
		if (parsed_to == (int)len && jobj && json_object_is_type(jobj, json_type_object)) {
			struct blob_buf blob = {};
			blob_buf_init(&blob, 0);
			blobmsg_add_object(&blob, jobj);
			wsubus_handle_msg(wsi, blob.head);
			blob_buf_free(&blob);
		} else {
			// parse error -> we just ignore the message
			lwsl_err("json parsing error %s, at char %d of %u, dropping msg\n",
					json_tokener_error_desc(tok_error), parsed_to, len);
			char *resp = jsonrpc_response_error(NULL, JSONRPC_ERRORCODE__PARSE_ERROR, NULL);
			wsubus_write_response_str(wsi, resp);
			free(resp);
		}
		wsubus_client_msg_reset(client);
	} else {
		if (tok_error != json_tokener_continue) {
			// parse error mid-message, client will send more data
			// For now we drop the client, but we could mark state and skip only this message
			lwsl_err("unexpected json parsing error %s\n", json_tokener_error_desc(tok_error));
			lwsl_err("Dropping client\n");

			// TODO check
			// stop reading and writing
			shutdown(lws_get_socket_fd(wsi), SHUT_RDWR);
		}
	}

	if (jobj)
		json_object_put(jobj);
}

static void wsubus_rx_blob(struct lws *wsi,
		const char *in,
		size_t len)
{
	// TODO implement
	lwsl_err("Binary (blobmsg) not implemented\n");
	// for now just do nothing with binary message
}

static void wsubus_rx(struct lws *wsi,
		const char *in,
		size_t len)
{
	size_t remaining_bytes_in_frame = lws_remaining_packet_payload(wsi);
	int is_final_frame = lws_is_final_fragment(wsi);

	struct wsubus_client_session *client = lws_wsi_user(wsi);

	lwsl_info("client %zu: msg final %d, len was %zu , remaining %zu\n",
			client->id, is_final_frame, len, remaining_bytes_in_frame);

	if (len > WSUBUS_MAX_MESSAGE_LEN || remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN ||
			client->curr_msg.len + len + remaining_bytes_in_frame > WSUBUS_MAX_MESSAGE_LEN) {
		// client intends to send too mush data, we will drop them
		lwsl_err("client %zu received fragment of frame (%zu total) making msg too long\n",
				client->id, len + remaining_bytes_in_frame);

		// TODO check
		// stop reading from mad client
		shutdown(lws_get_socket_fd(wsi), SHUT_RD);
	}

	if (lws_frame_is_binary(wsi)) {
		wsubus_rx_blob(wsi, in, len);
	} else {
		wsubus_rx_json(wsi, in, len);
	}
}

static int wsubus_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user,
		void *in,
		size_t len)
{
	//lwsl_debug("UBUS-JSON cb called with reason %d, wsi %p, user %p, in %p len %lu\n",
			//reason, wsi, user, in, len);

	//struct prog_context *prog = lws_context_user(lws_ctx);

	// all enum reasons listed for now. Will remove unneeded when complete.
	switch (reason) {
		// proto init-destroy (maybe will put init here)
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_notice("JSONPROTO: create proto\n");
		break;
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_notice("JSONPROTO: destroy proto\n");
		break;

		// new client is connecting
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("JSONPROTO: client handshake...\n");
		return wsubus_client_init(user)
			|| wsubus_filter(wsi);

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("JSONPROTO: established\n");
		break;

		// read/write
	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("JSONPROTO: protocol data received, len %lu\n", len);
		wsubus_rx(wsi, (char*)in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		lwsl_notice("JSONPROTO: wsi %p writable now\n", wsi);
		break;

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice("JSONPROTO: closed\n");
		wsubus_client_free(wsi, user);
		break;

		// debug for callbacks that should never happen
#ifndef NO_DEBUG_CALLBACKS
		// misc. Will we ever need this?
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
	case LWS_CALLBACK_GET_THREAD_ID:
	case LWS_CALLBACK_RECEIVE_PONG:
	case LWS_CALLBACK_USER:
		lwsl_err("JSONPROTO: unexpected misc callback reason %d\n", reason);
		assert (reason != reason);
		break;
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	case LWS_CALLBACK_WSI_CREATE:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
	case LWS_CALLBACK_WSI_DESTROY:
		lwsl_err("JSONPROTO: proto received net/WSI callback\n");
		assert(reason != reason);
		break;
	case LWS_CALLBACK_LOCK_POLL:
	case LWS_CALLBACK_UNLOCK_POLL:
	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_DEL_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
		lwsl_err("JSONPROTO: proto received fd callback\n");
		assert(reason != reason);
		break;
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_err("JSONPROTO: proto received http callback %d\n", reason);
		assert(reason != reason);
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		lwsl_err("JSONPROTO: proto received client callback %d\n", reason);
		assert(reason != reason);
		break;
#endif

	}
	return 0;
}

