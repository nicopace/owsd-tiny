/*
 * Copyright (C) 2016 Inteno Broadband Technology AB
 *
 * This software is the confidential and proprietary information of the
 * Inteno Broadband Technology AB. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the
 * license agreement you entered into with the Inteno Broadband Technology AB
 *
 * All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 */
/*
 * ubus over websocket - rpc parsing responses
 */
#pragma once

// TODO<deps> refactor curr_call blob_call somehow to not depend on its
// complete type here, just pointers
#include "rpc_call.h"
#include "rpc_list.h"
#include "rpc_sub.h"
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
		struct blob_attr *src_blob;
		struct ubusrpc_blob_call call;

		struct ubusrpc_blob_list list;

		struct ubusrpc_blob_sub sub;
		struct ubusrpc_blob_unsub_by_id unsub_by_id;
	};
	int (*handler)(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
};

int jsonrpc_blob_req_parse(struct jsonrpc_blob_req *req, const struct blob_attr *blob);

enum jsonrpc_error_code ubusrpc_blob_parse(struct ubusrpc_blob *ubusrpc, const char *method, struct blob_attr *params_blob);

