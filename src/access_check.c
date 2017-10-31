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
/* access checking functions */
#include "access_check.h"
#include "common.h"
#include "wsubus.impl.h"

#if WSD_HAVE_UBUS
#include <libubus.h>
#endif

#define SID_EXTENDED_PREFIX "X-"

/*
 * session ids that are hex chars are regular (rpcd) session IDs
 *
 * In some cases we don't want to ask rpcd session object for access. For these
 * uses we make up a "extended" session id, which is one that starts with "X-".
 */
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

/**
 * \brief Idea behind this access checker is to make it possible to deny login to users on some vhost
 */
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
				struct vh_context *vc = *(struct vh_context**)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
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
/**
 * \brief This access checker checks if the client is authenticated via TLS certificate. If so, access check is successful
 */
static enum wsu_ext_result wsu_ext_check_tls(struct lws *wsi)
{
	// return DEFAULT since next auth check may allow this session
	enum wsu_ext_result res = EXT_CHECK_DENY;

	if (!lws_is_ssl(wsi)) {
		res = EXT_CHECK_NEXT;
		goto exit;
	}
	union lws_tls_cert_info_results info = {0};
	size_t len = 64;

	int rc = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VERIFIED, &info, len);
	if (rc) {
		lwsl_notice("wsi %p TLS cert does not exist\n", wsi);
		goto exit;
	}
	if (!info.verified) {
		lwsl_notice("wsi %p TLS cert verification failure\n", wsi);
		goto exit;
	}
	res = EXT_CHECK_ALLOW;

#ifdef _DEBUG
	lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &info, len);
	lwsl_notice("wsi %p was TLS authenticated with cert CN = %s\n",
							wsi, info.ns.name);
#endif

exit:
	return res;
}
#endif

/*
 * the access check structure handle is implemented through a pending request,
 * either through ubus (because we asked rpcd session object for the access
 * decision) or through a defer-timeout, in case we have in-program logic to
 * check the permission.  Defer-timeout is used to make both ubus and local
 * in-program case asynchronous and avoid loop reentrancy.
 */
struct wsubus_access_check_req {
	bool result;
	wsubus_access_cb cb;

	void *ctx;

	enum {
#if WSD_HAVE_UBUS
		REQ_TAG_UBUS,
#endif
		REQ_TAG_DEFER,
	} tag;
	union {
#if WSD_HAVE_UBUS
		struct ubus_request ubus_req;
#endif
		struct uloop_timeout defer_timer;
	};
};

struct wsubus_access_check_req *wsubus_access_check_new(void)
{
	return calloc(1, sizeof(struct wsubus_access_check_req));
}

void wsubus_access_check_free(struct wsubus_access_check_req *req)
{
	free(req);
}

#if WSD_HAVE_UBUS
static void wsubus_access_check__on_ret(struct ubus_request *ureq, int type, struct blob_attr *msg)
{
	(void)type;

	struct wsubus_access_check_req *req = container_of(ureq, struct wsubus_access_check_req, ubus_req);

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
	struct wsubus_access_check_req *req = container_of(ureq, struct wsubus_access_check_req, ubus_req);

	// is ureq->status_code or status (the arg) what we want?
	req->cb(req, req->ctx, req->result && status == UBUS_STATUS_OK);
}

/**
 * \brief this access checker asks rpcd's session object on ubus for the
 * decision. ACLs from rpcd will apply (i.e. it does `ubus call session access`
 */
static int wsubus_access_check_via_session(
		struct wsubus_access_check_req *r,
		struct ubus_context *ubus_ctx,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	unsigned rem;
	struct blob_attr *cur;
	// does not allow ubus_rpc_session arg in params, as we will add it
	if (args) {
		blob_for_each_attr(cur, args->head, rem) {
			if (!strcmp("ubus_rpc_session", blobmsg_name(cur)))
				goto fail;
		}
	}

	int ret;
	uint32_t access_id;

	// look up ubus object names "session"
	if (ubus_lookup_id(ubus_ctx, "session", &access_id) != UBUS_STATUS_OK) {
		goto fail;
	}

	// construct call
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
		// we give the session object parameters "params" in hope some day
		// session object will actually be able to check arguments and not just
		// object/method names
		blobmsg_add_field(&blob_for_access, BLOBMSG_TYPE_TABLE, "params", blobmsg_data(args->head), blobmsg_len(args->head));
	}

	ret = ubus_invoke_async(ubus_ctx, access_id, "access", blob_for_access.head, &r->ubus_req);

	if (ret != UBUS_STATUS_OK) {
		goto fail_mem_blob;
	}

	r->tag = REQ_TAG_UBUS;
	r->ubus_req.data_cb = wsubus_access_check__on_ret;
	r->ubus_req.complete_cb = wsubus_access_check__cb;

	ubus_complete_request_async(ubus_ctx, &r->ubus_req);

	blob_buf_free(&blob_for_access);

	return 0;

fail_mem_blob:
	blob_buf_free(&blob_for_access);
fail:
	return -1;
}
#endif // WSD_HAVE_UBUS

static void deferral_cb(struct uloop_timeout *t) {
	struct wsubus_access_check_req *req = container_of(t, struct wsubus_access_check_req, defer_timer);
	assert(req->tag == REQ_TAG_DEFER);
	req->cb(req, req->ctx, req->result);
}

static int defer_callback(
		struct wsubus_access_check_req *req,
		void *ctx, bool result)
{
	// write result and make a timeout to call callback on next iteration of event loop
	req->tag = REQ_TAG_DEFER;
	req->result = result;
	req->defer_timer.cb = deferral_cb;
	return uloop_timeout_set(&req->defer_timer, 0);
}

int wsubus_access_check_(
		struct wsubus_access_check_req *req,
		struct lws *wsi,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	// this is the top-level entrypoint to access check, everything goes through it

	const char *esid = wsu_sid_extended(sid);

	req->cb = cb;
	req->ctx = ctx;

	enum wsu_ext_result res = EXT_CHECK_NEXT;
	// first, check if one of 2 checkers whitelists this call
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

	// see if checker made a decision or if it says to consult next one
	if (res != EXT_CHECK_NEXT) {
		// the checker made a decision, schedule firing of callback
		return defer_callback(req, ctx, res == EXT_CHECK_ALLOW);
	}

	// restrict calls only to some network interfaces
	res = wsu_ext_restrict_interface(wsi, sid, scope, object, method, args);
	if (res != EXT_CHECK_NEXT) {
		return defer_callback(req, ctx, res == EXT_CHECK_ALLOW);
	}

	// by default, if no checker has made decision until now, ask rpcd about it (or allow if no ubus support)
#if WSD_HAVE_UBUS
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	return wsubus_access_check_via_session(req, prog->ubus_ctx, sid, scope, object, method, args, ctx, cb);
#else
	return EXT_CHECK_ALLOW;
#endif
}

void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req)
{
	switch (req->tag) {
	case REQ_TAG_DEFER:
		uloop_timeout_cancel(&req->defer_timer);
		break;
#if WSD_HAVE_UBUS
	case REQ_TAG_UBUS:
		ubus_abort_request(ubus_ctx, &req->ubus_req);
		break;
#endif
	}
}
