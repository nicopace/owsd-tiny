#include "wsubus_access_check.h"

struct wsubus_access_check_req {
	struct ubus_request req;
	bool result;
	wsubus_access_cb cb;
};

static void wsubus_access_check__on_ret(struct ubus_request *ureq, int type, struct blob_attr *msg)
{
	(void)type;

	struct wsubus_access_check_req *req = container_of(ureq, struct wsubus_access_check_req, req);

	unsigned int rem;
	struct blob_attr *pos;
	blobmsg_for_each_attr(pos, msg, rem) {
		if (!strcmp("access", blobmsg_name(pos)) && blobmsg_type(pos) == BLOBMSG_TYPE_BOOL) {
			req->result = blobmsg_get_bool(pos);
			return;
		}
	}

	req->result = false;
}

static void wsubus_access_check__cb(struct ubus_request *ureq, int status)
{
	struct wsubus_access_check_req *req = container_of(ureq, struct wsubus_access_check_req, req);

	// is ureq->status_code or status (the arg) what we want?
	req->cb(req, req->req.priv, req->result && status == UBUS_STATUS_OK);
	free(req);
}

static struct wsubus_access_check_req * wsubus_access_check(
		struct ubus_context *ubus_ctx,
		const char *scope,
		const char *object,
		const char *method,
		const char *sid,
		void *ctx,
		wsubus_access_cb cb)
{
	struct wsubus_access_check_req *r = malloc(sizeof *r);
	if (!r) {
		goto fail;
	}

	int ret;
	uint32_t access_id;

	if (ubus_lookup_id(ubus_ctx, "session", &access_id) != UBUS_STATUS_OK) {
		goto fail_mem;
	}

	struct blob_buf blob_for_access = {};
	blob_buf_init(&blob_for_access, 0);

	blobmsg_add_string(&blob_for_access, "ubus_rpc_session", sid);
	blobmsg_add_string(&blob_for_access, "object", object);
	if (method)
		blobmsg_add_string(&blob_for_access, "function", method);
	if (scope)
		blobmsg_add_string(&blob_for_access, "scope", scope);

	ret = ubus_invoke_async(ubus_ctx, access_id, "access", blob_for_access.head, &r->req);

	if (ret != UBUS_STATUS_OK) {
		goto fail_mem_blob;
	}

	r->cb = cb;
	r->req.data_cb = wsubus_access_check__on_ret;
	r->req.complete_cb = wsubus_access_check__cb;
	r->req.priv = ctx;

	ubus_complete_request_async(ubus_ctx, &r->req);

	blob_buf_free(&blob_for_access);

	return r;

fail_mem_blob:
	blob_buf_free(&blob_for_access);
fail_mem:
	free(r);
fail:
	return NULL;
}

void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req)
{
	ubus_abort_request(ubus_ctx, &req->req);
	free(req);
}

struct wsubus_access_check_req * wsubus_access_check__call(
		struct ubus_context *ubus_ctx,
		const char *object,
		const char *method,
		const char *sid,
		void *ctx,
		wsubus_access_cb cb)
{
	return wsubus_access_check(ubus_ctx, NULL, object, method, sid, ctx, cb);
}

struct wsubus_access_check_req * wsubus_access_check__event(
		struct ubus_context *ubus_ctx,
		const char *event,
		const char *sid,
		void *ctx,
		wsubus_access_cb cb)
{
	return wsubus_access_check(ubus_ctx, "owsd", event, "read", sid, ctx, cb);
}

