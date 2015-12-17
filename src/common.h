#pragma once
#include <stddef.h>

struct prog_context {
	struct uloop_fd **ufds;
	size_t num_ufds;

	struct lws_context *lws_ctx;

	struct ubus_context *ubus_ctx;
};

