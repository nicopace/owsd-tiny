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

#include "common.h"
#include "rpc.h"

#include "access_check.h"

#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>

#include <json-c/json.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libwebsockets.h>

#define WSUBUS_PROTO_NAME "ubus-json"
#define WSUBUS_MAX_MESSAGE_LEN (1 << 27) // 128M

#define UBUS_DEFAULT_SID "00000000000000000000000000000000"
#define UBUS_SID_MAX_STRLEN 32

#define MAX_PROXIED_CALLS 20

/**
 * \brief lws allocates one instance of this for each websocket connection
 *
 * Used to store per-connection information and structures
 */
struct wsu_peer {
	// I/O
	struct {
		struct json_tokener *jtok;
		size_t len;
	} curr_msg; // read
	struct list_head write_q; // write

	char sid[UBUS_SID_MAX_STRLEN + 1];

	/**
	 * \brief enum tag + union is used to differentiate between client and server
	 */
	enum wsu_role {
		WSUBUS_ROLE_CLIENT = 1,
	} role;
	union {
		/**
		 * \brief stores per-connection data about active (connected) client
		 */
		struct wsu_client_session {
			unsigned int id;
			// used to track/cancel the long-lived handles or async requests
			struct list_head rpc_call_q;
			struct list_head access_check_q;
		} client;
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

static inline struct wsu_peer *wsu_client_to_peer(struct wsu_client_session *client)
{
	return container_of(client, struct wsu_peer, u.client);
}
//}}}

/**
 * \brief used to tie access_check_req context into list to be tracked/cancellable
 */
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

/**
 * \brief queue text data for writing to the other end of WebSocket
 *
 * \param wsi whom to write to
 * \param response_str what to write
 *
 * @return 0 if succeeded
 */
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

	lwsl_debug("sending reply: %.*s ... %p\n", len > 50 ? 50 : (int)len, response_str, w);
	int r = lws_callback_on_writable(wsi);

	if (r < 0) {
		lwsl_warn("error %d scheduling write callback\n", r);
		return -3;
	}

	return 0;
}
//}}}

static inline int wsu_sid_update(struct wsu_peer *peer, const char *sid)
{
	peer->sid[0] = '\0';
	strncat(peer->sid, sid, sizeof peer->sid - 1);
	return 0;
}

/**
 * \brief initializes the peer struct
 */
static inline int wsu_peer_init(struct wsu_peer *peer, enum wsu_role role)
{
	if (role == WSUBUS_ROLE_CLIENT) {
		static unsigned int clientid = 1;

		peer->u.client.id = clientid++;
		// these lists will keep track of async calls in progress
		INIT_LIST_HEAD(&peer->u.client.rpc_call_q);
		INIT_LIST_HEAD(&peer->u.client.access_check_q);
	} else {
		return -1;
	}

	peer->role = role;

	struct json_tokener *jtok = json_tokener_new();

	if (!jtok)
		return 1;

	// initialize the parser
	peer->curr_msg.len = 0;
	peer->curr_msg.jtok = jtok;
	INIT_LIST_HEAD(&peer->write_q);

	peer->sid[0] = '\0';
	return 0;
}

static inline void wsu_peer_deinit(struct lws *wsi, struct wsu_peer *peer)
{
	json_tokener_free(peer->curr_msg.jtok);
	peer->curr_msg.jtok = NULL;

	{
		// free everything from write queue
		struct wsu_writereq *p, *n;
		list_for_each_entry_safe(p, n, &peer->write_q, wq) {
			lwsl_info("free write in progress %p\n", p);
			list_del(&p->wq);
			free(p);
		}
	}

	if (peer->role == WSUBUS_ROLE_CLIENT) {
		struct prog_context *prog = lws_context_user(lws_get_context(wsi));

		// cancel each access check in progress
		//
		// NOTE:
		// it is important that first we cancel access checks in progress
		// (before cancelling calls in progress), since access check may
		// reference a pending call in progress (namely a call to ubus session
		// object)
		{
			struct wsubus_client_access_check_ctx *p, *n;
			list_for_each_entry_safe(p, n, &peer->u.client.access_check_q, acq) {
				lwsl_info("free check in progress %p\n", p);
				list_del(&p->acq);
				wsubus_access_check__cancel(prog->ubus_ctx, p->req);
				wsubus_access_check_free(p->req);
				if (p->destructor)
					p->destructor(p);
			}
		}

		{
			struct list_head *p, *n;
			// cancel all calls in progress
			list_for_each_safe(p, n, &peer->u.client.rpc_call_q) {
				list_del(p);
				struct ws_request_base *base = container_of(p, struct ws_request_base, cq);
				if (base->cancel_and_destroy) {
					lwsl_debug("free req in progress %p\n", base);
					base->cancel_and_destroy(base);
				}
			}
		}
	}
}

/**
 * \brief when lws calls writable callback, this function drains the write
 * queue using lws_write until we can't write anymore
 */
static inline int wsubus_tx_text(struct lws *wsi)
{
	struct wsu_peer *peer = wsi_to_peer(wsi);

	struct wsu_writereq *w, *other;

	list_for_each_entry_safe(w, other, &peer->write_q, wq) {
		do {
			int written = lws_write(wsi, w->buf + LWS_SEND_BUFFER_PRE_PADDING + w->written, w->len - w->written, LWS_WRITE_TEXT);

			if (written < 0) {
				lwsl_err("peer IO: error %d in writing\n", written);
				// TODO<lwsclose> check
				// stop reading and writing
				shutdown(lws_get_socket_fd(wsi), SHUT_RDWR);
				return -1;
			}

			w->written += (size_t)written;
		} while (w->written < w->len && !lws_partial_buffered(wsi));

		if (w->written == w->len) {
			lwsl_notice("peer IO: fin write %zu\n", w->len);
			list_del(&w->wq);
			free(w);
		}
		if (lws_partial_buffered(wsi)) {
			lwsl_notice("client IO: partial buffered");
			lws_callback_on_writable(wsi);
			break;
		}
	}

	return 0;
}
