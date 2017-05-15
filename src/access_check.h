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

/* for use by RPCs that need access check */
#pragma once

#include <stdbool.h>
#include <stddef.h>

struct lws;
struct blob_buf;
struct ubus_context;

/**
 * \brief structure representing access check in progress, opaque to callers
 */
struct wsubus_access_check_req;

/**
 * \brief creates a new access check request structure
 */
struct wsubus_access_check_req *wsubus_access_check_new(void);

/**
 * \brief free the access check structure
 */
void wsubus_access_check_free(struct wsubus_access_check_req *req);

/**
 * \brief typedef for functions that are used as access check callback
 *
 * \param req request for which the callback is firing
 * \param ctx user context
 * \param allow result of the access check - true if allowed false otherwise
 */
typedef void (*wsubus_access_cb) (struct wsubus_access_check_req *req, void *ctx, bool allow);

/** \brief internal function called other access check functions */
int wsubus_access_check_(
		struct wsubus_access_check_req *req,
		struct lws *wsi,
		const char *sid,
		const char *scope,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb);

/**
 * \brief cancel an access check that is in progress
 */
void wsubus_access_check__cancel(struct ubus_context *ubus_ctx, struct wsubus_access_check_req *req);

/**
 * \brief check if the RPC call is allowed for givent client with given session identifier
 *
 * \param req access check structure
 * \param wsi which web socket the request is related to
 * \param sid session id against which to check the call
 * \param object name of object being called
 * \param method name of method being called
 * \param args argumetns for the call. Access checks may modify
 * arguments, caller should make sure to use same buffer for check and call to allow that
 * \param ctx user pointer, returned in callback
 * \param cb callback to call when access check is done
 *
 * @return 0 on success
 */
static inline int wsubus_access_check__call(
		struct wsubus_access_check_req *req,
		struct lws *wsi,
		const char *sid,
		const char *object,
		const char *method,
		struct blob_buf *args,
		void *ctx,
		wsubus_access_cb cb)
{
	// scope is used when access check goes to rpcd session ubus object, NULL means default scope which is ubus
	return wsubus_access_check_(req, wsi, sid, NULL, object, method, args, ctx, cb);
}

/**
 * \brief check if the given client with session id is allowed to be notified that a bus event happened
 *
 * \param req access check structure
 * \param wsi which web socket the request is related to
 * \param sid session id against which to check the call
 * \param event name of event that happened
 * \param data data inside event that happened. May be modified by access check
 * \param ctx user pointer, returned in callback
 * \param cb callback to call when access check is done
 *
 * @return 0 on success
 */
static inline int wsubus_access_check__event(
		struct wsubus_access_check_req *req,
		struct lws *wsi,
		const char *sid,
		const char *event,
		struct blob_buf *data,
		void *ctx,
		wsubus_access_cb cb)
{
	// when access check goes to rpcd session ubus object, "owsd" is used as
	// custom scope, under which "read" permission means that event is allowed
	// to be heard by such-and-such user group. The custom scope is done to
	// isolate event permissions from maybe-identically-named object/method
	// permissions.
	return wsubus_access_check_(req, wsi, sid, "owsd", event, "read", data, ctx, cb);
}
