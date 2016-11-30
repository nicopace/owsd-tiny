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
#pragma once
#include <stddef.h>
#include <libwebsockets.h>
#include <libubus.h>

struct prog_context {
	struct uloop_fd **ufds;
	size_t num_ufds;

	struct uloop_timeout utimer;

	struct lws_context *lws_ctx;

	struct ubus_context *ubus_ctx;

	const char *www_path;
	const char *redir_from;
	const char *redir_to;
};

// each listen vhost keeps origin whitelist
struct vh_context {
	struct list_head origins;
	char *name;
};
struct origin {
	struct list_head list;
	const char *url;
};


// the vhost for clients has list of client infos so they can be reconnected
struct clvh_context {
	struct list_head clients;
};

struct reconnect_info {
	struct list_head list;
	struct lws *wsi;
	int reconnect_count;
	struct uloop_timeout timer;
	struct lws_client_connect_info cl_info;
};
