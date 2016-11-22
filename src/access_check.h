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

#include <libubus.h>

struct wsubus_access_check_req;

typedef void (*wsubus_access_cb) (struct wsubus_access_check_req *req, void *ctx, bool allow);

struct wsubus_access_check_req * wsubus_access_check__call(
		struct ubus_context *ubus_ctx,
		const char *object,
		const char *method,
		const char *sid,
		void *ctx,
		wsubus_access_cb cb);

struct wsubus_access_check_req * wsubus_access_check__event(
		struct ubus_context *ubus_ctx,
		const char *event,
		const char *sid,
		void *ctx,
		wsubus_access_cb cb);

void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req);
