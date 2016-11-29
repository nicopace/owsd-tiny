#pragma once

#include <stdlib.h>
#include <libubus.h>
#include <libubox/uloop.h>

struct prog_context {
	struct uloop_fd ufd;

	struct lws_context *lws_ctx;

	char *ubus_path;

	struct ubus_context ubus_ctx;
};
