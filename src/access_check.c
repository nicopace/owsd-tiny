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
#include "access_check.h"
#include "common.h"

#define SID_EXTENDED_PREFIX "X-"

static inline const char* wsu_sid_extended(const char *sid)
{
	return strstr(sid, SID_EXTENDED_PREFIX) == sid ? sid+strlen(SID_EXTENDED_PREFIX) : NULL;
}

enum wsu_ext_result {
	EXT_CHECK_NEXT, EXT_CHECK_ALLOW, EXT_CHECK_DENY
};

static enum wsu_ext_result wsu_ext_check_interface(struct lws *wsi)
{
	// TODO implement, to support case where a vhost (interface) doesn't require login
	return EXT_CHECK_NEXT;
}

static enum wsu_ext_result wsu_ext_restrict_interface(struct lws *wsi,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args)
{
	(void)scope; (void)sid;
	if (!strcmp(object, "session") && !strcmp(method, "login")) {
		unsigned rem;
		struct blob_attr *cur;
		blobmsg_for_each_attr(cur, args->head, rem) {
			if (!strcmp("username", blobmsg_name(cur))) {
				struct vh_context *vc = lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
				if (!list_empty(&vc->users)) {
					struct str_list *s;
					list_for_each_entry(s, &vc->users, list)
						if (!strcmp(s->str, blobmsg_get_string(cur)))
							return EXT_CHECK_ALLOW;
					return EXT_CHECK_DENY;
				}
			}
		}
	}

	return EXT_CHECK_NEXT;
}


#ifdef LWS_OPENSSL_SUPPORT
static enum wsu_ext_result wsu_ext_check_tls(struct lws *wsi)
{
	if (!lws_is_ssl(wsi)) {
		return EXT_CHECK_NEXT;
	}

	struct wsu_peer *peer = wsi_to_peer(wsi);
	SSL *ssl = lws_get_ssl(wsi);
	X509 *x = SSL_get_peer_certificate(ssl);
	int have_cert = !!x;
	X509_free(x);
	if (have_cert && SSL_get_verify_result(ssl) == X509_V_OK) {
#ifdef _DEBUG
		X509_NAME *xname = X509_get_subject_name(x);
		X509_NAME_get_text_by_NID(xname, NID_commonName, peer->tls.cert_subj, sizeof peer->tls.cert_subj);
		lwsl_notice("wsi %p was TLS authenticated with cert CN= %s\n", wsi, peer->tls.cert_subj);
#endif
		return EXT_CHECK_ALLOW;
	} else {
		lwsl_notice("wsi %p was not TLS authenticated\n", wsi);
		// return DEFAULT since next auth check may allow this session
		return EXT_CHECK_DENY;
	}
}
#endif

struct wsubus_access_check_req {
	struct ubus_request req;
	bool result;
	wsubus_access_cb cb;
};

static struct wsubus_access_check_req fake_request;

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

static struct wsubus_access_check_req * wsubus_access_check_via_session(
		struct ubus_context *ubus_ctx,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	struct wsubus_access_check_req *r = malloc(sizeof *r);
	if (!r) {
		goto fail;
	}

	unsigned rem;
	struct blob_attr *cur;
	// does not allow ubus_rpc_session arg in params, as we will add it
	if (args) {
		blob_for_each_attr(cur, args->head, rem) {
			if (!strcmp("ubus_rpc_session", blobmsg_name(cur)))
				goto fail_mem;
		}
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
	if (args) {
		blobmsg_add_string(args, "ubus_rpc_session", sid);
		blobmsg_add_field(&blob_for_access, BLOBMSG_TYPE_TABLE, "params", blobmsg_data(args->head), blobmsg_len(args->head));
	}

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

struct wsubus_access_check_req* wsubus_access_check_(
		struct lws *wsi,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	const char *esid = wsu_sid_extended(sid);

	// for now ext_allow isnt async, so do everyhing here instead of cb,ctx,req wrapper
	enum wsu_ext_result res = EXT_CHECK_NEXT;
	if (esid) {
		if (!strcmp("mgmt-interface", esid)) {
			res = wsu_ext_check_interface(wsi);
		}
#ifdef LWS_OPENSSL_SUPPORT
		else if (!strcmp("tls-certificate", esid)) {
			res = wsu_ext_check_tls(wsi);
		}
#endif
	}

	if (res != EXT_CHECK_NEXT) {
		// fire the cb here, since we won't be doing async access check
		cb(&fake_request, ctx, res == EXT_CHECK_ALLOW);
		return &fake_request;
	}

	res = wsu_ext_restrict_interface(wsi, sid, scope, object, method, args);

	if (res != EXT_CHECK_NEXT) {
		// fire the cb here, since we won't be doing async access check
		cb(&fake_request, ctx, res == EXT_CHECK_ALLOW);
		return &fake_request;
	}

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	return wsubus_access_check_via_session(prog->ubus_ctx, sid, scope, object, method, args, ctx, cb);
}

void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req)
{
	assert(req != &fake_request);
	ubus_abort_request(ubus_ctx, &req->req);
	free(req);
}
