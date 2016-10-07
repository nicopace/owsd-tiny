/*
 * Copyright (C) 2016 Inteno Broadband Technology AB
 *
 * This software is the confidential and proprietary information of the
 * Inteno Broadband Technology AB. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the
 * license agreement you entered into with the Inteno Broadband Technology AB
 *
 * All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 */
#include "ws_http.h"
#include "ws_http_serve.h"
#include "common.h"

#include <libubox/uloop.h>

#include <libwebsockets.h>

#include <errno.h>
#include <assert.h>

static lws_callback_function ws_http_cb;

struct lws_protocols ws_http_proto = {
	/*  we don't want any subprotocol name to match this, and it won't */
	NULL,
	ws_http_cb,
	// following other fields we don't use:
	0,    // - per-session data size
	0,    // - max rx buffer size
	0,    // - id
	NULL, // - user pointer
};

static inline short
eventmask_ufd_to_pollfd(unsigned int ufd_events)
{
	return
		(ufd_events & ULOOP_READ  ? POLLIN  : 0) |
		(ufd_events & ULOOP_WRITE ? POLLOUT : 0);
}
static inline unsigned int
eventmask_pollfd_to_ufd(int pollfd_events)
{
	return
		(pollfd_events & POLLIN  ? ULOOP_READ  : 0) |
		(pollfd_events & POLLOUT ? ULOOP_WRITE : 0);
}

static void ufd_service_cb(struct uloop_fd *ufd, unsigned int revents)
{
	extern struct prog_context global;

	lwsl_debug("servicing fd %d with ufd eventmask %x %s%s\n", ufd->fd, revents,
			revents & ULOOP_READ ? "R" : "", revents & ULOOP_WRITE ? "W" : "");
	struct pollfd pfd;

	pfd.events = eventmask_ufd_to_pollfd(ufd->flags);
	pfd.revents = eventmask_ufd_to_pollfd(revents);
	pfd.fd = ufd->fd;

	if (ufd->eof) {
		pfd.revents |= POLLHUP;
		lwsl_debug("ufd HUP on %d\n", ufd->fd);
	}
	if (ufd->error) {
		pfd.revents |= POLLERR;
		lwsl_debug("ufd ERR on %d\n", ufd->fd);
	}

	lws_service_fd(global.lws_ctx, &pfd);

	for (int count = 30; count && !lws_service_adjust_timeout(global.lws_ctx, 1, 0); --count) {
		lwsl_notice("re-service pipelined data\n");
		lws_plat_service_tsi(global.lws_ctx, -1, 0);
	}
}

static int ws_http_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user __attribute__((unused)),
		void *in,
		size_t len)
{
	struct lws_pollargs *in_pollargs = (struct lws_pollargs*)in;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	int rc;

	(void)len;

	switch (reason) {
		// fd handling
	case LWS_CALLBACK_ADD_POLL_FD: {
		lwsl_notice("add fd %d mask %x\n", in_pollargs->fd, in_pollargs->events);

		assert(in_pollargs->fd >= 0 && in_pollargs->fd > 0 && (size_t)in_pollargs->fd < prog->num_ufds);
		assert(prog->ufds[in_pollargs->fd] == NULL);

		struct uloop_fd *ufd = calloc(1, sizeof *ufd);

		if (!ufd) {
			lwsl_err("error allocating ufd: %s\n", strerror(errno));
			return 1;
		}

		ufd->fd = in_pollargs->fd;
		ufd->cb = ufd_service_cb;

		if (uloop_fd_add(ufd, eventmask_pollfd_to_ufd(in_pollargs->events))) {
			lwsl_err("error adding fd: %s\n", strerror(errno));
			free(ufd);
			return 1;
		}

		prog->ufds[in_pollargs->fd] = ufd;

		return 0;
	}

	case LWS_CALLBACK_DEL_POLL_FD: {
		lwsl_notice("del fd %d\n", in_pollargs->fd);

		assert(in_pollargs->fd >= 0 && in_pollargs->fd > 0 && (size_t)in_pollargs->fd < prog->num_ufds);
		// TODO LWS shouldn't call us if we didn't manage to add fd. for now ignore if not added
		// TODO is this a LWS 'bug'?
		// assert(prog->ufds[in_pollargs->fd] != NULL);
		if (prog->ufds[in_pollargs->fd] == NULL)
			return 0;

		uloop_fd_delete(prog->ufds[in_pollargs->fd]);

		free(prog->ufds[in_pollargs->fd]);
		prog->ufds[in_pollargs->fd] = NULL;

		return 0;
	}

	case LWS_CALLBACK_CHANGE_MODE_POLL_FD: {
		lwsl_notice("modify fd %d to mask %x %s%s\n", in_pollargs->fd, in_pollargs->events,
				in_pollargs->events & POLLIN ? "IN" : "", in_pollargs->events & POLLOUT ? "OUT" : "");

		assert(in_pollargs->fd >= 0 && in_pollargs->fd > 0 && (size_t)in_pollargs->fd < prog->num_ufds);
		assert(prog->ufds[in_pollargs->fd] != NULL);

		struct uloop_fd *ufd = prog->ufds[in_pollargs->fd];

		assert(ufd->fd == in_pollargs->fd);
		assert(ufd->cb == ufd_service_cb);
		assert(ufd->registered == true);

		if (eventmask_pollfd_to_ufd(in_pollargs->events) != ufd->flags) {
			if (uloop_fd_add(ufd, eventmask_pollfd_to_ufd(in_pollargs->events))) {
				return 1;
			}
		}

		return 0;
	}

		// deny websocket clients with default (no) subprotocol
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("client handshaking without subproto - denying\n");
		return 1;

		// temporary - libwebsockets 1.7+ calls this always... TODO lwsbug
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
		return 0;

	case LWS_CALLBACK_HTTP:	 {
		return ws_http_serve_file(wsi, in);
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_info("http request writable again %s\n", in);
		rc = lws_serve_http_file_fragment(wsi);
		return ws_http_serve_interpret_retcode(wsi, rc);

	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_info("http callback %d\n", reason);
		return 0;

	case LWS_CALLBACK_RECEIVE_PONG:
		break;

	default:
		break;
	}

	return 0;
}

