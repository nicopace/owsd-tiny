#pragma once

#include <stdlib.h>

struct prog_context {
	struct ubus_context *ubus_ctx;
	const char *origin;

	size_t num_ufds;

	struct pollfd *ufds;

	struct lws_context *lws_ctx;

};
