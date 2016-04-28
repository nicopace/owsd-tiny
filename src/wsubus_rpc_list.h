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
 * ubus over websocket - ubus list
 */
#pragma once

#include <stdint.h>

struct ubusrpc_blob_list {
	struct blob_attr *src_blob;

	const char *pattern;
};

struct ubusrpc_blob;
struct lws;

int ubusrpc_blob_list_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

int ubusrpc_handle_list(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
