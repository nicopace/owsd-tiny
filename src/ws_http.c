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
#include "common.h"

#include <libubox/uloop.h>

#include <libwebsockets.h>

#include <errno.h>

#include <assert.h>

static callback_function ws_http_cb;

struct lws_protocols ws_http_proto = {
	/*  we don't want any subprotocol name to match this, and it won't
	 *  match since will split on the ',' character.
	 *
	 *  TODO maybe NULL is correct here, but see lws-issues.txt */
	" , ", 
	ws_http_cb,
	// following other fields we don't use:
	// - per-session data size
	// - max rx buffer size
	// - id
	// - user pointer 
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

static void ufd_service_cb (struct uloop_fd *ufd, unsigned int events)
{
	extern struct prog_context global;

	lwsl_debug("servicing fd %d with ufd eventmask %x %s%s\n", ufd->fd, events,
			events & ULOOP_READ ? "R" : "", events & ULOOP_WRITE ? "W" : "");
	struct pollfd pfd;

	pfd.revents = eventmask_ufd_to_pollfd(events);
	pfd.fd = ufd->fd;
	lws_service_fd(global.lws_ctx, &pfd);
}

static int ws_http_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user __attribute__((unused)),
		void *in,
		size_t len)
{

	//lwsl_debug("http cb called with reason %d, wsi %p, user %p, in %p len %lu\n",
			//reason, wsi, user, in, len);

	struct lws_pollargs *in_pollargs = (struct lws_pollargs*)in;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	// all enum reasons listed for now. Will remove unneeded when complete.
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

		// locking the fd polling table - we won't need this (single thread)
	case LWS_CALLBACK_LOCK_POLL:
		lwsl_info("lock poll\n");
		break;
	case LWS_CALLBACK_UNLOCK_POLL:
		lwsl_info("unlock poll\n");
		break;

		// proto init-destroy (maybe will put init here)
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_notice("create proto\n");
		break;
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_notice("destroy proto\n");
		break;

		// new client is connecting
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		lwsl_notice("network client connected\n");
		break;
	case LWS_CALLBACK_WSI_CREATE:
		lwsl_notice("created wsi\n");
		break;
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		lwsl_notice("instantiated client\n");
		break;
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("client handshaking without subproto - denying\n");
		return 1;
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_err("non-protocol client establihed!\n");
		assert(false);
		break;

		// read/write
	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("protocol data received, len %lu\n", len);
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		lwsl_notice("wsi %p writable now\n", wsi);
		break;

		// client is leaving
	case LWS_CALLBACK_CLOSED:
		lwsl_notice("closed\n");
		break;
	case LWS_CALLBACK_WSI_DESTROY:
		lwsl_notice("destroyed wsi\n");
		break;

		// maybe needed if we will serve html
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_info("http callback %d\n", reason);
		// for now close connection/reject...
		return 1;

#ifndef NO_DEBUG_CALLBACKS
		// misc. Will we ever need these?
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
	case LWS_CALLBACK_GET_THREAD_ID:
	case LWS_CALLBACK_RECEIVE_PONG:
	case LWS_CALLBACK_USER:
		lwsl_err("unexpected misc callback reason %d\n", reason);
		assert(reason != reason);
		break;
		// we are server, we don't need to handle these...
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		lwsl_err("Client callback reason received: %d\n", reason);
		assert(reason != reason);
		break;
#endif

	}

	return 0;
}

