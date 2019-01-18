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
#include "ws_http.h"
#include "ws_http_serve.h"
#include "common.h"

#include <libubox/uloop.h>

#include <libwebsockets.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

/*
 * libwebsockets protocols[0] handler
 *
 * In libwebsockets the protocols[0] is special i.e. this callback receives
 * some type of events unrelated to client connection/disconnection and actual
 * websocket connection.
 */


static lws_callback_function ws_http_cb;

struct lws_protocols ws_http_proto = {
	/* because we only want to use this callback/protocol for poll integration,
	 * management and pre-websocket stuff, we don't want any subprotocol name
	 * to match this and negotiate a connection under this subprotocol */
	",,,,,,,,",
	ws_http_cb,
	// following other fields we don't use:
	0,    // - per-session data size
	0,    // - max rx buffer size
	0,    // - id
	NULL, // - user pointer
};

// {{{ event bitmask conversions
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
		(pollfd_events & POLLOUT ? ULOOP_WRITE : 0) |
		ULOOP_ERROR_CB;
}
// }}}

/**
 * \brief Called by uloop when read/writable events happen
 *
 * \param ufd poller structure describing fd that received the event
 * \param revents bitmask of events that happened on the fd
 */
static void ufd_service_cb(struct uloop_fd *ufd, unsigned int revents)
{
	extern struct prog_context global;

	lwsl_debug("servicing fd %d with ufd eventmask %x %s%s\n", ufd->fd, revents,
			revents & ULOOP_READ ? "R" : "", revents & ULOOP_WRITE ? "W" : "");

	// libwebsockets' poll integration expects to receive a 'struct pollfd'
	// like from poll(2) . To integrate libwebsockets with uloop we thus need
	// to convert uloop's polling structs and masks to pollfd
	struct pollfd pfd;

	// convert the polling mode flags
	pfd.events = eventmask_ufd_to_pollfd(ufd->flags);
	// convert the event that happened
	pfd.revents = eventmask_ufd_to_pollfd(revents);
	pfd.fd = ufd->fd;

	// additionally uloop stores error and hangup condition outside the event
	// mask, whereas pollfd has it in-band with the event mask. So, manually
	// restore those bits as well.
	if (ufd->eof) {
		pfd.revents |= POLLHUP;
		lwsl_debug("ufd HUP on %d\n", ufd->fd);
	}
	if (ufd->error) {
		pfd.revents |= LWS_POLLHUP;
		lwsl_debug("ufd ERR on %d\n", ufd->fd);
	}

	// forward the struct to inform libwebsockets about the event
	lws_service_fd(global.lws_ctx, &pfd);

	// in case one read event resulted in multiple logical requests (e.g.
	// multiple HTTP GET requests pipelined and received at once),
	// libwebsockets will only process part of it (probably such a default
	// gives more control to the external dispatching loop). Anyway, we want to
	// re-service libwebosockets to drain the data until everything has been
	// processed.
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

	(void)len;

	switch (reason) {

#ifdef LWS_WITH_CGI
	case LWS_CALLBACK_CGI_STDIN_DATA:	 /* POST body for stdin */
	case LWS_CALLBACK_CGI_TERMINATED:
	case LWS_CALLBACK_CGI:
	case LWS_CALLBACK_HTTP_WRITEABLE:
		return lws_callback_http_dummy(wsi, reason, user, in, len);
#endif
		// fd handling
	case LWS_CALLBACK_ADD_POLL_FD: {
		// libwebsockets wants us to watch a new fd
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
		// libwebsockets wants us to stop watching some fd
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
		// libwebsockets wants us to modify event flags on watched fd
		lwsl_notice("modify fd %d to mask %x %s%s\n", in_pollargs->fd, in_pollargs->events,
				in_pollargs->events & POLLIN ? "IN" : "", in_pollargs->events & POLLOUT ? "OUT" : "");

		assert(in_pollargs->fd >= 0 && in_pollargs->fd > 0 && (size_t)in_pollargs->fd < prog->num_ufds);
		assert(prog->ufds[in_pollargs->fd] != NULL);

		struct uloop_fd *ufd = prog->ufds[in_pollargs->fd];

		assert(ufd->fd == in_pollargs->fd);
		assert(ufd->cb == ufd_service_cb);

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

		// plain HTTP request received
	case LWS_CALLBACK_HTTP:	 {
		// we have custom HTTP serving logic called from here
		return ws_http_serve_file(wsi, in);
	}
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_info("http callback %d\n", reason);
		return 0;
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_RECEIVE_PONG:
		break;

	default:
		break;
	}

	return 0;
}

