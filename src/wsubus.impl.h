/*
 * ubus over websocket - used to implement individual rpc methods
 */
#pragma once
#include <stddef.h>

#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

#include <libubox/list.h>

#define UBUS_DEFAULT_SID "00000000000000000000000000000000"

struct wsubus_client_session {
	unsigned int id;

	struct {
		struct json_tokener *jtok;

		size_t len;
	} curr_msg;

	struct list_head rpc_call_q;
	struct list_head access_check_q;
	struct list_head write_q;

	char *last_known_sid;
};

struct wsubus_client_access_check_ctx {
	struct wsubus_access_check_req *req;
	void (*destructor)(struct wsubus_client_access_check_ctx *);
	struct list_head acq;
};

struct wsubus_client_writereq {
	unsigned char *buf;
	size_t len;

	size_t written;

	struct list_head wq;
};

struct lws;

int wsubus_write_response_str(struct lws *wsi, const char *response_str);

int wsubus_check_and_update_sid(struct wsubus_client_session *client, const char *sid);
