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

#include "common.h"
#include "wsubus.h"

#include <libubox/uloop.h>

#include <libwebsockets.h>

#include <getopt.h>
#include <assert.h>

#define WSD_2str_(_) #_
#define WSD_2str(_) WSD_2str_(_)

struct prog_context global;

static lws_callback_function ws_http_cb;

struct lws_protocols ws_http_proto = {
	/*  we don't want any subprotocol name to match this, and it won't */
	"sdfasdf",
	ws_http_cb,
	// following other fields we don't use:
	0,    // - per-session data size
	0,    // - max rx buffer size
	0,    // - id
	NULL, // - user pointer
};

void utimer_service(struct uloop_timeout *utimer)
{
	lws_service_fd(global.lws_ctx, NULL);
	uloop_timeout_set(utimer, 1000);
}

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
}

static int ws_http_cb(struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user __attribute__((unused)),
		void *in,
		size_t len __attribute__((unused)))
{
	struct lws_pollargs *in_pollargs = (struct lws_pollargs*)in;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));


	switch (reason) {
		// fd handling
	case LWS_CALLBACK_ADD_POLL_FD: {
		lwsl_notice("add fd %d mask %x\n", in_pollargs->fd, in_pollargs->events);

		assert(prog->ufd.fd == -1);

		prog->ufd.fd = in_pollargs->fd;
		prog->ufd.cb = ufd_service_cb;

		if (uloop_fd_add(&prog->ufd, eventmask_pollfd_to_ufd(in_pollargs->events))) {
			lwsl_err("error adding fd: %s\n", strerror(errno));
			prog->ufd.fd = -1;
			return 1;
		}

		return 0;
	}

	case LWS_CALLBACK_DEL_POLL_FD: {
		lwsl_notice("del fd %d\n", in_pollargs->fd);

		if (prog->ufd.fd == -1)
			return 0;

		assert(prog->ufd.fd == in_pollargs->fd);

		uloop_fd_delete(&prog->ufd);
		prog->ufd.fd = -1;

		return 0;
	}

	case LWS_CALLBACK_CHANGE_MODE_POLL_FD: {
		lwsl_notice("modify fd %d to mask %x %s%s\n", in_pollargs->fd, in_pollargs->events,
				in_pollargs->events & POLLIN ? "IN" : "", in_pollargs->events & POLLOUT ? "OUT" : "");

		assert(prog->ufd.fd == in_pollargs->fd);
		assert(prog->ufd.cb == ufd_service_cb);
		assert(prog->ufd.registered == true);

		if (eventmask_pollfd_to_ufd(in_pollargs->events) != prog->ufd.flags) {
			if (uloop_fd_add(&prog->ufd, eventmask_pollfd_to_ufd(in_pollargs->events))) {
				return 1;
			}
		}

		return 0;
	}

	case LWS_CALLBACK_WSI_DESTROY:
		uloop_end();
		return 0;

		// deny websocket clients with default (no) subprotocol
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("client handshaking without subproto - denying\n");
		return 1;
	default:
		return 0;
	}
}


void print_usage(const char *argv0)
{
	fprintf(stderr,
			"Usage: %s [ <options> ] <host> <port>\n"
			"  -o <origin>      origin url address to use\n"
			"  -S               SSL cert path\n"
			"\n", argv0);
}

int main(int argc, char *argv[])
{
	int rc = 0;

	struct lws_context_creation_info lws_info = {};
	struct lws_client_connect_info wsi_info = {};

	lws_info.options = LWS_SERVER_OPTION_DISABLE_IPV6;

	int c;
	while ((c = getopt(argc, argv, "o:Sh")) != -1) {
		switch (c) {
		case 'o':
			wsi_info.origin = optarg;
			break;
		case '6':
			lws_info.options &= ~LWS_SERVER_OPTION_DISABLE_IPV6;
			break;
		case 'S':
			wsi_info.ssl_connection = 1;
			lws_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		case 'h':
		default:
			print_usage(argv[0]);
			return c == 'h' ? 0 : -2;
		}
	}

	if (argc < 3) {
		print_usage(argv[0]);
		return -1;
	}

	argc -= optind;
	argv += optind;

	lws_set_log_level(-1, NULL);

	uloop_init();

	lws_info.port = -1;
	lws_info.uid = -1;
	lws_info.gid = -1;
	lws_info.user = &global;
	lws_info.protocols = (struct lws_protocols[]) {
		ws_http_proto,
		wsubus_proto,
		{ NULL, NULL, }
	};

	lwsl_debug("Creating lws context\n");

	struct lws_context *lws_ctx = lws_create_context(&lws_info);
	if (!lws_ctx) {
		lwsl_err("lws_create_context error\n");
		rc = 1;
		goto no_lws;
	}

	global.lws_ctx = wsi_info.context = lws_ctx;
	global.ufd.fd = -1;
	wsi_info.address = argv[0];
	wsi_info.host = argv[0];
	if (!wsi_info.origin) {
		wsi_info.origin = argv[0];
	}
	wsi_info.path = "/";
	wsi_info.protocol = "ubus-json";

	char *error;
	wsi_info.port = strtol(argv[1], &error, 10);
	if (*error) {
		lwsl_err("invalid port number\n");
		goto no_connect;
	}


	struct lws *wsi = lws_client_connect_via_info(&wsi_info);
	if (!wsi) {
		lwsl_err("could not connect, exiting\n");
		goto no_connect;
	}

	struct uloop_timeout utimer = {};
	utimer.cb = utimer_service;
	uloop_timeout_add(&utimer);
	uloop_timeout_set(&utimer, 1000);

	lwsl_info("running uloop...\n");
	uloop_run();

no_connect:

	lws_context_destroy(lws_ctx);
no_lws:


	return rc;
}
