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
 * ubus over websocket - rpc parsing responses
 */
#pragma once

#include "rpc_call.h"
#include "rpc_list.h"
#include "rpc_sub.h"
#include "rpc_login.h"
#include "util_jsonrpc.h"

struct jsonrpc_blob_req {
	struct blob_attr *id;
	const char *version;
	const char *method;
	struct blob_attr *params;
};

struct lws;

struct ubusrpc_blob {
	union {
		struct {
			struct blob_attr *src_blob;
			const char *sid;
		};

		struct ubusrpc_blob_call call;

		struct ubusrpc_blob_list list;

		struct ubusrpc_blob_sub sub;
		struct ubusrpc_blob_unsub_by_id unsub_by_id;

		struct ubusrpc_blob_login login;
	};
	int (*handler)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
};

int jsonrpc_blob_req_parse(struct jsonrpc_blob_req *req, const struct blob_attr *blob);

enum jsonrpc_error_code ubusrpc_blob_parse(struct ubusrpc_blob *ubusrpc, const char *method, struct blob_attr *params_blob);
