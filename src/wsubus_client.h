#ifndef WSUBUS_CLIENT_H
#define WSUBUS_CLIENT_H

/*
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Authors:
 *	Reidar
 *	Alex
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

#include <libwebsockets.h>
#include <libubus.h>


#define CREATE_UBUS_OBJECT(_name, _methods) \
	{ \
		.name = _name, \
		.type = &(struct ubus_object_type) \
			UBUS_OBJECT_TYPE(_name, _methods), \
		.methods = _methods, \
		.n_methods = ARRAY_SIZE(_methods) \
	}

enum client_type {
	CLIENT_TYPE_UNKNOWN = 0,
	CLIENT_FROM_PROGARG,
	CLIENT_FROM_UBUS
};

int wsubus_client_create(const char *addr, const int port, const char *path, enum client_type type);
void wsubus_client_enable_proxy(void);
int wsubus_client_start_proxying(struct lws_context *lws_ctx, struct ubus_context *ubus_ctx);
void wsubus_client_set_cert_filepath(const char *filepath);
void wsubus_client_set_private_key_filepath(const char *filepath);
void wsubus_client_set_ca_filepath(const char *filepath);
void wsubus_client_connect_all(void);
void wsubus_client_connect_retry(struct lws *wsi);
void wsubus_client_reconnect(struct lws *wsi);
void wsubus_client_clean(void);
bool wsubus_client_should_destroy(struct lws *wsi);
void wsubus_client_destroy(struct lws *wsi);

#endif /* WSUBUS_CLIENT_H */
