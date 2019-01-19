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
#pragma once

#include <libwebsockets.h>
#include <libubox/uloop.h>
#include <stddef.h>

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
	struct list_head users;
	char *name;
};
struct str_list {
	struct list_head list;
	const char *str;
};
