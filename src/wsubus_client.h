#if WSD_HAVE_UBUSPROXY
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

extern int ubusx_prefix;

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
/* wsubus connection states */
enum connection_state {
	CONNECTION_STATE_DISCONNECTED,
	CONNECTION_STATE_CONNECTING,
	CONNECTION_STATE_CONNECTED,
	CONNECTION_STATE_TEARINGDOWN
};

// the vhost for clients has list of client infos so they can be reconnected
struct clvh_context {
	bool enabled; /* enable WS ubus client proxy functionality */
	struct list_head clients; /* list of clients to proxy */
	struct lws_context *plws_ctx;
	struct lws_vhost *pclvh;
	struct list_head paths;
	struct avl_tree paths_tree;
};

struct client_connection_info {
	int index;
	struct list_head list;
	struct lws *wsi;
	int reconnect_count;
	struct uloop_timeout timer;
	struct lws_client_connect_info connection_info;
	enum client_type type;
	enum connection_state state;
};

int wsubus_client_create(const char *addr, const int port, const char *path, enum client_type type);
void wsubus_client_enable_proxy(void);
int wsubus_client_start_proxying(struct lws_context *lws_ctx, struct ubus_context *ubus_ctx);
void wsubus_client_set_cert_filepath(const char *filepath);
void wsubus_client_set_private_key_filepath(const char *filepath);
void wsubus_client_set_ca_filepath(const char *filepath);
void wsubus_client_set_rpcd_integration(bool connect_to_rpcd);
bool wsubus_client_get_rpcd_integration(void);
void wsubus_client_connect_all(void);
void wsubus_client_connect_retry(struct lws *wsi);
void wsubus_client_reconnect(struct lws *wsi);
void wsubus_client_clean(void);
void wsubus_client_set_state(struct lws *wsi, enum connection_state state);
bool wsubus_client_should_destroy(struct lws *wsi);
void wsubus_client_destroy(struct lws *wsi);
void wsubus_client_path_pattern_add(const char *pattern);
bool wsubus_client_match_pattern(const char *name);

#endif /* WSUBUS_CLIENT_H */
#endif /* WSD_HAVE_UBUSPROXY */
