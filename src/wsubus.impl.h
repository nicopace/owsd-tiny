/*
 * ubus over websocket - used to implement individual rpc methods
 */
#pragma once
#include <stddef.h>

#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

// TODO<deps> refactor curr_call context_call somehow to not depend on its
// complete type here, just pointers
#include "wsubus_rpc_call.h"

struct wsubus_client_session {
	unsigned int id;

	struct {
		struct json_tokener *jtok;

		size_t len;
	} curr_msg;

	struct wsubus_context_call curr_call;
};

struct lws;

int wsubus_write_response_str(struct lws *wsi, const char *response_str);

void wsubus_client_call_reset(struct wsubus_client_session *client);
