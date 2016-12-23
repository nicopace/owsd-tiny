/*
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/*
 * ubus over websocket - used to implement individual rpc methods
 */
#pragma once
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>

#include <json-c/json.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include <libwebsockets.h>

#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

#define UBUS_DEFAULT_SID "00000000000000000000000000000000"
#define UBUS_SID_MAX_STRLEN 32

#define MAX_PROXIED_CALLS 20

struct wsu_peer {
	enum wsu_role {
		WSUBUS_ROLE_CLIENT = 1,
		WSUBUS_ROLE_REMOTE,
	} role;

	// I/O
	struct {
		struct json_tokener *jtok;
		size_t len;
	} curr_msg; // read
	struct list_head write_q; // write

	char sid[UBUS_SID_MAX_STRLEN + 1];

	union {
		struct wsu_client_session {
			unsigned int id;

			struct list_head rpc_call_q;
			struct list_head access_check_q;
		} client;

		struct wsu_remote_bus {
			int call_id;

			struct {
				unsigned int login  : 1;
				unsigned int listen : 1;
				unsigned int call   : MAX_PROXIED_CALLS;
				int list_id;
			} waiting_for;

			struct wsu_proxied_call {
				int jsonrpc_id;
				struct ubus_request_data ureq;
			} calls[MAX_PROXIED_CALLS];

			struct lws *wsi;
			struct avl_tree stubs;
		} remote;
	} u;
};

//{{{ wsi userdata getters
static inline struct wsu_peer *wsi_to_peer(struct lws *wsi)
{
	struct wsu_peer *p = lws_wsi_user(wsi);
	assert(p);
	assert(p->role);
	return p;
}
static inline struct wsu_client_session *wsi_to_client(struct lws *wsi)
{
	struct wsu_peer *p = wsi_to_peer(wsi);
	assert(p->role == WSUBUS_ROLE_CLIENT);
	return &p->u.client;
}
static inline struct wsu_remote_bus *wsi_to_remote(struct lws *wsi)
{
	struct wsu_peer *p = wsi_to_peer(wsi);
	assert(p->role == WSUBUS_ROLE_REMOTE);
	return &p->u.remote;
}
static inline struct wsu_peer *wsu_remote_to_peer(struct wsu_remote_bus *remote)
{
	return container_of(remote, struct wsu_peer, u.remote);
}
static inline struct wsu_peer *wsu_client_to_peer(struct wsu_client_session *client)
{
	return container_of(client, struct wsu_peer, u.client);
}
//}}}

//{{{ accessors for remote.calls collection
static inline struct wsu_proxied_call *wsu_proxied_call_new(struct wsu_remote_bus *remote)
{
	unsigned call_idx = ffs(~remote->waiting_for.call);
	if (!call_idx || call_idx > MAX_PROXIED_CALLS) {
		return NULL;
	}
	--call_idx;

	remote->waiting_for.call |= (1U << call_idx);

	return &remote->calls[call_idx];
}
static inline void wsu_proxied_call_free(struct wsu_remote_bus *remote, struct wsu_proxied_call *p)
{
	int idx = p - remote->calls;
	if (idx >= 0 && idx < MAX_PROXIED_CALLS)
		remote->waiting_for.call &= ~(1U << idx);
}

#define _wsu_lowbit(X) ((X) & (-X))

#define wsu_proxied_call_foreach(REMOTE, P) \
	for (int _mask_##REMOTE = (REMOTE->waiting_for.call), _callbit_##REMOTE = _wsu_lowbit(_mask_##REMOTE), _idx_##REMOTE; \
			(_callbit_##REMOTE = _wsu_lowbit(_mask_##REMOTE)) \
			&& (_idx_##REMOTE = __builtin_ctz(_callbit_##REMOTE), P = &REMOTE->calls[_idx_##REMOTE], \
				_callbit_##REMOTE); \
			_mask_##REMOTE &= ~_callbit_##REMOTE)

//}}}

struct wsubus_client_access_check_ctx {
	struct wsubus_access_check_req *req;
	void (*destructor)(struct wsubus_client_access_check_ctx *);
	struct list_head acq;
};

//{{{ I/O handling
struct wsu_writereq {
	size_t len;
	size_t written;

	struct list_head wq;

	unsigned char buf[0];
};

static inline int wsu_queue_write_str(struct lws *wsi, const char *response_str)
{
	struct wsu_peer *peer = wsi_to_peer(wsi);
	if (!response_str) {
		lwsl_err("Not writing null message\n");
		return -1;
	}

	size_t len = strlen(response_str);

	assert(len < WSUBUS_MAX_MESSAGE_LEN);

	struct wsu_writereq *w = malloc(sizeof *w
			+ LWS_SEND_BUFFER_PRE_PADDING
			+ len
			+ LWS_SEND_BUFFER_POST_PADDING);
	if (!w) {
		lwsl_err("failed to alloc ubus response buf");
		return -2;
	}

	memcpy(w->buf+LWS_SEND_BUFFER_PRE_PADDING, response_str, len);

	w->len = len;
	w->written = 0;

	list_add_tail(&w->wq, &peer->write_q);

	lwsl_debug("sending reply: %.*s ... %p, %d\n", len > 50 ? 50 : len, response_str, w);
	int r = lws_callback_on_writable(wsi);

	if (r < 0) {
		lwsl_warn("error %d scheduling write callback\n");
		return -3;
	}

	return 0;
}

static inline void wsu_read_reset(struct wsu_peer *peer)
{
	peer->curr_msg.len = 0;

	json_tokener_reset(peer->curr_msg.jtok);
}
//}}}

static inline int wsu_check_and_update_sid(struct wsu_peer *peer, const char *sid)
{
	if (*peer->sid == '\0') {
		strncat(peer->sid, sid, sizeof peer->sid);
		return 0;
	}
	if (!strcmp(peer->sid, UBUS_DEFAULT_SID)) {
		peer->sid[0] = '\0';
		strncat(peer->sid, sid, sizeof peer->sid - 1);
		return 0;
	}

	if (strcmp(peer->sid, sid)) {
		return 1;
	}
	return 0;
}
