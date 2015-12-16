#pragma once

struct prog_context {
	struct uloop_fd **ufds;
	int num_ufds;

	struct libwebsocket_context *lws_ctx;

	struct ubus_context *ubus_ctx;
};

