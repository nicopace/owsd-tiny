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
 * ubus over websocket - ubus call
 */
#pragma once

struct ubusrpc_blob_call {
	struct blob_attr *src_blob;

	const char *sid;
	const char *object;
	const char *method;
	struct blob_buf *params_buf;
};

struct lws;
struct ubusrpc_blob;
struct list_head;

void wsubus_percall_ctx_destroy_h(struct list_head *lh);

int ubusrpc_blob_call_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

int ubusrpc_handle_call(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id);
