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

#include <libubus.h>

struct wsubus_access_check_req;

typedef void (*wsubus_access_cb) (struct wsubus_access_check_req *req, void *ctx, bool allow);

struct wsubus_access_check_req* wsubus_access_check_(
		struct lws *wsi,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb);

void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req);

static inline struct wsubus_access_check_req * wsubus_access_check__call(
		struct lws *wsi,
		const char *sid,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	return wsubus_access_check_(wsi, sid, NULL, object, method, args, ctx, cb);
}

static inline struct wsubus_access_check_req * wsubus_access_check__event(
		struct lws *wsi,
		const char *sid,
		const char *event,
		struct blob_buf *data,
		void *ctx,
		wsubus_access_cb cb)
{
	return wsubus_access_check_(wsi, sid, "owsd", event, "read", data, ctx, cb);
}
