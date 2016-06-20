#pragma once

#include <stdlib.h>
#include <libubox/uloop.h>

struct prog_context {
	struct uloop_fd ufd;

	struct lws_context *lws_ctx;

};
