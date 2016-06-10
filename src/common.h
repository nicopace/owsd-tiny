#pragma once

#include <stdlib.h>
#include <libubox/uloop.h>

struct prog_context {
	struct ubus_context *ubus_ctx;
	const char *origin;

	struct uloop_fd ufd;

	struct lws_context *lws_ctx;

};
