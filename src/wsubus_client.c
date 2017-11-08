/*
 * Copyright (C) 2016 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: Reidar Cederqvist <reidar.cederqvist@gmail.com>
 * Author: Ionut-Alex Oprea <ionutalexoprea@gmail.com>
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

/*
 * ubus over websocket - client session handling
 */

#include "wsubus_client.h"
#include "wsubus.h"
#include "ws_http.h"
#include "common.h"

#include <libubox/blobmsg.h>
#include <libubus.h>

// id counter to give all clients a unique id
/* static unsigned long id; */
// contains list of urls where to connect as ubus proxy
static struct lws_context_creation_info clvh_info = {};
// FIXME to support different certs per different client, this becomes per-client

static struct clvh_context connect_infos = {
	.enabled = false,
	.clients = LIST_HEAD_INIT(connect_infos.clients)
};

void wsubus_client_enable_proxy(void)
{
	connect_infos.enabled = true;
}

static void utimer_reconnect_cb(struct uloop_timeout *timer)
{
	struct reconnect_info *c = container_of(timer, struct reconnect_info, timer);
	if(!c)
		lwsl_err("no client owning this timer\n");
	lwsl_notice("connecting as client too to %s %d\n", c->cl_info.address, c->cl_info.port);
	lws_client_connect_via_info(&c->cl_info);
}

int wsubus_client_create(const char *addr, int port, const char *path, enum client_type type)
{
	lwsl_notice("addr = %s, port = %d, path = %s\n", addr, port, path);
	struct reconnect_info *newcl = malloc(sizeof *newcl);

	if (!newcl) {
		lwsl_err("OOM clinfo init\n");
		return -1;
	}

	struct lws_protocols ws_protocols[] = {
		ws_http_proto,
		ws_ubusproxy_proto,
		{ }
	};

	newcl->wsi = NULL;
	newcl->timer = (struct uloop_timeout){};
	newcl->timer.cb = utimer_reconnect_cb;
	newcl->cl_info = (struct lws_client_connect_info){};

	newcl->cl_info.port = port;
	newcl->cl_info.address = addr;
	newcl->cl_info.host = addr;
	newcl->cl_info.path = path;
	newcl->cl_info.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	newcl->cl_info.pwsi = &newcl->wsi;
	newcl->type = type;
	newcl->reconnect_count = 0;

	newcl->cl_info.vhost = connect_infos.pclvh;
	newcl->cl_info.context = connect_infos.plws_ctx;
	newcl->cl_info.protocol = ws_protocols[1].name;

	list_add_tail(&newcl->list, &connect_infos.clients);

	wsubus_client_enable_proxy();

	/* if client is added from ubus the vhost is already running */
	/* so the connection can be started here */
	if (type == CLIENT_FROM_UBUS)
		uloop_timeout_set(&newcl->timer, 100);

	lwsl_notice("done adding client\n");
	return 0;
}

static void _wsubus_client_connect(struct lws *wsi, int timeout)
{
	struct reconnect_info *client;

	if(!wsi) {
		list_for_each_entry(client, &connect_infos.clients, list) {
			lwsl_notice("test connect client %s\n", client->cl_info.address);
			client->reconnect_count = 0;
			uloop_timeout_set(&client->timer, timeout);
		}
	} else {
		list_for_each_entry(client, &connect_infos.clients, list) {
			if(client->wsi == wsi) {
				client->reconnect_count = 0;
				uloop_timeout_set(&client->timer, timeout);
				break;
			}
		}
	}
}

/* connect all clients */
void wsubus_client_connect_all(void)
{
	_wsubus_client_connect(NULL, 0);
}	

/* retry connection on error */
void wsubus_client_connect_retry(struct lws *wsi)
{
	struct reconnect_info *client;

	if(!wsi)
		return;
	list_for_each_entry(client, &connect_infos.clients, list) {
		if(client->wsi == wsi) {
			uloop_timeout_set(&client->timer, (++client->reconnect_count * 2000));
			break;
		}
	}
}

/* retry connection on disconnect */
void wsubus_client_reconnect(struct lws *wsi)
{
	_wsubus_client_connect(wsi, 2000);
}


/* ################################### */
/* ######## UBUS RELATED CODE ######## */
/* ################################### */

enum {
	CLIENT_ADD_IP,
	CLIENT_ADD_PORT,
	__CLIENT_ADD_MAX
};

static const struct blobmsg_policy add_client_policy[__CLIENT_ADD_MAX] = {
	[CLIENT_ADD_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[CLIENT_ADD_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	CLIENT_ID,
	__CLIENT_ID_MAX
};

static const struct blobmsg_policy client_id_policy[__CLIENT_ID_MAX] = {
	[CLIENT_ID] = { .name = "ip", .type = BLOBMSG_TYPE_INT32 },
};

int    add_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int remove_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int   list_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int clear_clients(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);

#define WSUBUS_UBUS_OBJECT_NAME "owsd.ubusproxy"
#define WSS_PORT 443

struct ubus_method ubus_methods[] = {
	UBUS_METHOD("add", add_client, add_client_policy),
	UBUS_METHOD("remove", remove_client, client_id_policy),
	UBUS_METHOD("list", list_client, client_id_policy),
	UBUS_METHOD_NOARG("clear", clear_clients),
};

struct ubus_object object = CREATE_UBUS_OBJECT(WSUBUS_UBUS_OBJECT_NAME, ubus_methods);

int add_client(struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_ADD_MAX];
	int port = WSS_PORT, ret;

	blobmsg_parse(add_client_policy, __CLIENT_ADD_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(tb[CLIENT_ADD_IP]))
		return UBUS_STATUS_INVALID_ARGUMENT;
	//TODO: validate IP

	if (tb[CLIENT_ADD_PORT])
		port = blobmsg_get_u32(tb[CLIENT_ADD_PORT]);

	if (port <= 0 || port >= 1 << 16)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ret = wsubus_client_create(blobmsg_get_string(tb[CLIENT_ADD_IP]),
			port, "/", CLIENT_FROM_UBUS);

	if(ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

int remove_client(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_ID_MAX];

	blobmsg_parse(add_client_policy, __CLIENT_ID_MAX, tb, blob_data(msg), blob_len(msg));
	return UBUS_STATUS_OK;
}

int list_client(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_ID_MAX];

	blobmsg_parse(add_client_policy, __CLIENT_ID_MAX, tb, blob_data(msg), blob_len(msg));
	return UBUS_STATUS_OK;
}

int clear_clients(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

/* ####################################### */
/* ######## END UBUS RELATED CODE ######## */
/* ####################################### */


int wsubus_client_start_proxying(struct lws_context *lws_ctx, struct ubus_context *ubus_ctx)
{
	if (!connect_infos.enabled)
		return -1;

	if(	!clvh_info.ssl_cert_filepath ||
		!clvh_info.ssl_private_key_filepath ||
		!clvh_info.ssl_ca_filepath)
		return -2;

	struct lws_protocols ws_protocols[] = {
		ws_http_proto,
		ws_ubusproxy_proto,
		{ }
	};

	clvh_info.port = CONTEXT_PORT_NO_LISTEN;
	clvh_info.protocols = ws_protocols;
	clvh_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS;

	struct lws_vhost *clvh = lws_create_vhost(lws_ctx, &clvh_info);
	if (!clvh) {
		lwsl_err("lws_create_vhost failed\n");
		return -3;
	}

	struct reconnect_info *c;
	connect_infos.pclvh = clvh;
	connect_infos.plws_ctx = lws_ctx;

	/** This has to be done again for configured clients because when
	 * they are created the client virtual host (clvh) and the lws
	 * context are not yet created.
	 */
	list_for_each_entry(c, &connect_infos.clients, list) {
		c->cl_info.vhost = clvh;
		c->cl_info.context = lws_ctx;
	}

	// Setup ubus object
	ubus_add_object(ubus_ctx, &object);

	return 0;
}

void wsubus_client_set_cert_filepath(const char *filepath)
{
	clvh_info.ssl_cert_filepath = filepath;
}

void wsubus_client_set_private_key_filepath(const char *filepath)
{
	clvh_info.ssl_private_key_filepath = filepath;
}

void wsubus_client_set_ca_filepath(const char *filepath)
{
	clvh_info.ssl_ca_filepath = filepath;
}

/* delete one client */
void wsubus_client_del(struct reconnect_info *c)
{
	uloop_timeout_cancel(&c->timer);
	list_del(&c->list);
	free(c);
}

/* free the info for connection as ubus proxy / delete all clients */
void wsubus_client_clean(void)
{
	struct reconnect_info *c, *tmp;

	list_for_each_entry_safe(c, tmp, &connect_infos.clients, list)
		wsubus_client_del(c);
}
