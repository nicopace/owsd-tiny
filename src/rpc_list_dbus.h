/*
 * Copyright (C) 2017 Inteno Broadband Technology AB. All rights reserved.
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
#pragma once

#include "rpc.h"

struct ubusrpc_blob;
struct blob_attr;
struct lws;

struct wsd_list_ctx {
	union {
		struct ws_request_base;
		struct ws_request_base _base;
	};

	struct DBusMessage *list_reply;
	int reply_slot;

	struct DBusPendingCall *call_req;

	struct list_head introspectables;
};

void wsd_list_ctx_cancel_and_destroy(struct ws_request_base *base);

int handle_list_dbus(struct ws_request_base *req, struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
