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
 * ubus over websocket - ubus event subscription
 */
#pragma once

#include <stdint.h>
#include "rpc.h"

struct ubusrpc_blob_sub {
	union {
		struct ubusrpc_blob;
		struct ubusrpc_blob _base;
	};

	const char *pattern;
};

struct ubusrpc_blob;
struct lws;

struct ubusrpc_blob* ubusrpc_blob_sub_parse(struct blob_attr *blob);
struct ubusrpc_blob* ubusrpc_blob_sub_list_parse(struct blob_attr *blob);

int ubusrpc_handle_sub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
int ubusrpc_handle_sub_list(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
int ubusrpc_handle_unsub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
