#pragma once
#include <stddef.h>

#include <libubus.h>

struct prog_context {
	struct uloop_fd **ufds;
	size_t num_ufds;

	struct lws_context *lws_ctx;

	struct ubus_context *ubus_ctx;

	struct origin *origin_list;
};

struct origin {
	struct list_head list;
	char *url;
};
