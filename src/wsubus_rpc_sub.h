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
 * ubus over websocket - ubus event subscription
 */
#pragma once

#include <stdint.h>

// TODO maybe these will be same type
struct ubusrpc_blob_sub {
	struct blob_attr *src_blob;

	const char *sid;
	const char *pattern;
};

struct ubusrpc_blob_unsub_by_id {
	struct blob_attr *src_blob;

	const char *sid;
	uint32_t id;
};

struct ubusrpc_blob;
struct lws;

void wsubus_clean_all_subscriptions(void);

int wsubus_unsubscribe_by_wsi_and_id(struct lws *wsi, uint32_t id);
int wsubus_unsubscribe_by_wsi_and_pattern(struct lws *wsi, const char *pattern);
int wsubus_unsubscribe_all_by_wsi(struct lws *wsi);

int ubusrpc_blob_sub_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);
int ubusrpc_blob_sub_list_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);
int ubusrpc_blob_unsub_by_id_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob);

int ubusrpc_handle_sub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
int ubusrpc_handle_sub_list(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
int ubusrpc_handle_unsub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
int ubusrpc_handle_unsub_by_id(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id);
