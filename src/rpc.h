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

#include "util_jsonrpc.h"
#include <libubox/list.h>

/**
 * \brief stores the generic components of a JSON-RPC request
 */
struct jsonrpc_blob_req {
	struct blob_attr *id;
	const char *version;
	const char *method;
	struct blob_attr *params;
};

struct lws;

/**
 * \brief Base structure for keeping track of asynchronous requests
 */
struct ws_request_base {
	struct lws *wsi;

	struct blob_attr *id;
	struct blob_buf retbuf;

	/**
	 * \brief this list_head is chained into clients' rpc_call_q list. That way each client has list of we_request_base-derived objects
	 */
	struct list_head cq;

	/**
	 * \brief call this to cancel the in-progress request, and free any
	 * request-specific resources that were acquired. Requests that base on top
	 * of the request struct, and have resources/create a request, should fill
	 * this in with method that will free all resources including the common
	 * parts
	 */
	void (*cancel_and_destroy)(struct ws_request_base *ctx);
};

/**
 * \brief base structure for storing parsed RPC arguments
 */
struct ubusrpc_blob {
	struct blob_attr *src_blob;
	const char *sid;

	/**
	 * \brief parse for this RPC should fill in this pointer. When called, should execute the rpc and return 0
	 */
	int (*handler)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);

	/**
	 * \brief parse for this RPC should fill in this pointer. When called,
	 * should free all aadditional resources and then call destroy_default at
	 * the end, to clean up the common parts
	 */
	void (*destroy)(struct ubusrpc_blob*);
};

void ubusrpc_blob_destroy_default(struct ubusrpc_blob *ubusrpc_);

/**
 * \brief parse a JSON-RPC request. Parses only the generic fields and leaves
 * RPC-specific stuff as blobs. returns 0 on success
 *
 * \param req request to fill with parsed components
 * \param blob the blob (binary json) to parse
 */
int jsonrpc_blob_req_parse(struct jsonrpc_blob_req *req, const struct blob_attr *blob);

/**
 * \brief depending on given JSONRPC method, calls appropriate parse callback
 * to parse the params blob and set up handler pointer
 *
 * \param method the RPC method name we are parsing
 * \param params_blob parameters of RPC method that we want to parse
 * \param err where to store error code if any
 *
 * @return Parsed structure with filled-in handler callback and parameter data, or NULL
 */
struct ubusrpc_blob * ubusrpc_blob_parse(const char *method, struct blob_attr *params_blob, enum jsonrpc_error_code *err);
