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
#include <arpa/inet.h>

#define MAX_IP_LEN 128
#define MAX_PATH_LEN 128

// contains list of urls where to connect as ubus proxy
static struct lws_context_creation_info clvh_info = {};
// FIXME to support different certs per different client, this becomes per-client

static struct clvh_context connect_infos = {
	.enabled = false,
	.clients = LIST_HEAD_INIT(connect_infos.clients)
};

void insert_at_lowest_free_index(struct client_connection_info *client, struct list_head *head)
{
	struct client_connection_info *tmp;
	int i = 0;

	list_for_each_entry(tmp, head, list) {
		if (tmp->index > i) {
			client->index = i;
			list_add_tail(&client->list, &tmp->list);
			return;
		}
		i++;
	}
	client->index = i;
	list_add_tail(&client->list, &tmp->list);
}

void wsubus_client_enable_proxy(void)
{
	connect_infos.enabled = true;
}

static void utimer_reconnect_cb(struct uloop_timeout *timer)
{
	struct lws *wsi = NULL;
	struct client_connection_info *c = container_of(timer, struct client_connection_info
 , timer);
	if(!c)
		lwsl_err("no client owning this timer\n");
	lwsl_notice("connecting as client too to %s %d\n",
			c->connection_info.address, c->connection_info.port);
	wsi = lws_client_connect_via_info(&c->connection_info);
	if (!wsi)
		return;
	wsubus_client_set_state(wsi, CONNECTION_STATE_CONNECTING);
}

static bool validate_ip_port_path(const char *addr, int *port, const char *path)
{
	int rv;
	struct in_addr in_addr_dummy;
	struct in6_addr in6_addr_dummy;

	if (!addr || !path) {
		lwsl_err("invalid arguments\n");
		return false;
	}

	rv = inet_pton(AF_INET, addr, &in_addr_dummy); /* returns 1 on success */
	if (!rv)
		rv = inet_pton(AF_INET6, addr, &in6_addr_dummy);
	if (!rv) {
		lwsl_err("invalid ip address\n");
		return false;
	}

	if (*port <= 0 || *port >= 1<<16) {
		lwsl_err("invalid port (%d), using 443\n", *port);
		*port = 443;
	}

	return true;
}

static bool unique_ip(const char *addr)
{
	struct client_connection_info *client;

	list_for_each_entry(client, &connect_infos.clients, list)
		if (strcmp(client->connection_info.address, addr) == 0)
			return false;

	return true;
}

int wsubus_client_create(const char *addr, int port, const char *path, enum client_type type)
{
	struct client_connection_info *newcl;
	char *_addr, *_path;

	if (!validate_ip_port_path(addr, &port, path))
		goto invalid_argument;

	if (!unique_ip(addr))
		goto invalid_argument;

	newcl = malloc(sizeof *newcl);
	if (!newcl) {
		lwsl_err("OOM clinfo init\n");
		goto error_cl;
	}

	_addr = (char *)calloc(MAX_IP_LEN, sizeof(char));
	if (!_addr)
		goto error_addr;

	_path = (char *)calloc(MAX_PATH_LEN, sizeof(char));
	if (!_path)
		goto error_path;

	strncpy(_addr, addr, MAX_IP_LEN);
	strncpy(_path, path, MAX_PATH_LEN);

	struct lws_protocols ws_protocols[] = {
		ws_http_proto,
		ws_ubusproxy_proto,
		{ }
	};

	newcl->wsi = NULL;
	newcl->timer = (struct uloop_timeout){};
	newcl->timer.cb = utimer_reconnect_cb;
	newcl->type = type;
	newcl->reconnect_count = 0;
	newcl->state = CONNECTION_STATE_DISCONNECTED;

	newcl->connection_info = (struct lws_client_connect_info){};

	newcl->connection_info.path = _path;
	newcl->connection_info.address = _addr;
	newcl->connection_info.host = _addr;
	newcl->connection_info.port = port;
	newcl->connection_info.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	newcl->connection_info.pwsi = &newcl->wsi;
	newcl->connection_info.vhost = connect_infos.pclvh;
	newcl->connection_info.context = connect_infos.plws_ctx;
	newcl->connection_info.protocol = ws_protocols[1].name;

	insert_at_lowest_free_index(newcl, &connect_infos.clients);

	wsubus_client_enable_proxy();

	/** if client is added from ubus the vhost is already running
	 * so the connection can be started here
	 */
	if (type == CLIENT_FROM_UBUS)
		uloop_timeout_set(&newcl->timer, 100);

	lwsl_notice("done adding client\n");
	return 0;

error_path:
	free(_addr);
error_addr:
	free(newcl);
error_cl:
	return UBUS_STATUS_UNKNOWN_ERROR;
invalid_argument:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

static void _wsubus_client_connect(struct lws *wsi, int timeout)
{
	struct client_connection_info *client;

	if(!wsi) {
		list_for_each_entry(client, &connect_infos.clients, list) {
			lwsl_notice("test connect client %s\n", client->connection_info.address);
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
	struct client_connection_info *client;

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
	CLIENT_INDEX,
	__CLIENT_INDEX_MAX
};

static const struct blobmsg_policy client_index_policy[__CLIENT_INDEX_MAX] = {
	[CLIENT_INDEX] = { .name = "index", .type = BLOBMSG_TYPE_INT32 },
};

int    add_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int remove_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int   list_client(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
int clear_clients(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);

#define WSUBUS_UBUS_OBJECT_NAME "owsd.ubusproxy"
#define WSS_PORT 443

struct ubus_method ubus_methods[] = {
	UBUS_METHOD("add", add_client, add_client_policy),
	UBUS_METHOD("remove", remove_client, client_index_policy),
	UBUS_METHOD("list", list_client, client_index_policy),
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

	return ret;
}

/** To delete a client you need to wait until it is writeable. That's done
 * by triggering the lws_callback_on_writeable and then in the callback
 * figure out if the callback was triggered to send data or to get destroyed
 */
int remove_client(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_INDEX_MAX];
	unsigned int index;
	bool found = false;
	struct client_connection_info *client;

	blobmsg_parse(client_index_policy, __CLIENT_INDEX_MAX, tb, blob_data(msg), blob_len(msg));

	if(!(tb[CLIENT_INDEX]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	index = blobmsg_get_u32(tb[CLIENT_INDEX]);

	list_for_each_entry(client, &connect_infos.clients, list) {
		if (index == (long)client->index) {
			found = true;
			break;
		}
	}

	if (!found)
		return UBUS_STATUS_INVALID_ARGUMENT;

	switch (client->state) {
		case CONNECTION_STATE_DISCONNECTED:
			wsubus_client_destroy(client->wsi);
			break;
		case CONNECTION_STATE_CONNECTING:
			client->state = CONNECTION_STATE_TEARINGDOWN;
			break;
		case CONNECTION_STATE_CONNECTED:
			client->state = CONNECTION_STATE_TEARINGDOWN;
			lws_callback_on_writable(client->wsi);
			break;
		case CONNECTION_STATE_TEARINGDOWN:
		default:
			break;
	}

	return UBUS_STATUS_OK;
}

static void dump_client(struct blob_buf *bb, struct client_connection_info *client)
{
	char clname[16];
	void *t;
	bool has_ssl;

	snprintf(clname, 16, "proxy-%d", client->index);
	has_ssl = client->connection_info.ssl_connection &
		(LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK) ?
		true : false;

	t = blobmsg_open_table(bb, clname);
	blobmsg_add_u32(bb, "index", client->index);
	blobmsg_add_string(bb, "ip", client->connection_info.address);
	blobmsg_add_u32(bb, "port", client->connection_info.port);
	blobmsg_add_string(bb, "path", client->connection_info.path);
	blobmsg_add_string(bb, "protocol", client->connection_info.protocol);
	blobmsg_add_u8(bb, "SSL", has_ssl);
	blobmsg_add_string(bb, "type", (client->type == CLIENT_FROM_UBUS ? "ubus" : "uci"));
	/* blobmsg_add_u8(bb, "connected", client->connected); */
	blobmsg_add_u32(bb, "state", client->state);
	blobmsg_close_table(bb, t);
}

int list_client(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_INDEX_MAX];
	struct client_connection_info *client;
	struct blob_buf bb = {};
	long index = -1;

	blobmsg_parse(client_index_policy, __CLIENT_INDEX_MAX, tb, blob_data(msg), blob_len(msg));

	blob_buf_init(&bb, 0);

	if(tb[CLIENT_INDEX])
		index = blobmsg_get_u32(tb[CLIENT_INDEX]);

	list_for_each_entry(client, &connect_infos.clients, list) {
		if (index == -1)
			dump_client(&bb, client);
		else if (index == (long)client->index) {
			dump_client(&bb, client);
			break;
		}
	}

	ubus_send_reply(ctx, req, bb.head);

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

	struct client_connection_info *c;
	connect_infos.pclvh = clvh;
	connect_infos.plws_ctx = lws_ctx;

	/** This has to be done again for configured clients because when
	 * they are created the client virtual host (clvh) and the lws
	 * context are not yet created.
	 */
	list_for_each_entry(c, &connect_infos.clients, list) {
		c->connection_info.vhost = clvh;
		c->connection_info.context = lws_ctx;
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
void wsubus_client_del(struct client_connection_info *c)
{
	uloop_timeout_cancel(&c->timer);
	free((char *)c->connection_info.address);
	free((char *)c->connection_info.path);
	list_del(&c->list);
	free(c);
}

/* free the info for connection as ubus proxy / delete all clients */
void wsubus_client_clean(void)
{
	struct client_connection_info *c, *tmp;

	list_for_each_entry_safe(c, tmp, &connect_infos.clients, list)
		wsubus_client_del(c);
}

void wsubus_client_set_state(struct lws *wsi, enum connection_state state)
{
	struct client_connection_info *client;

	list_for_each_entry(client, &connect_infos.clients, list)
		if (wsi == client->wsi)
			client->state = state;
}

bool wsubus_client_should_destroy(struct lws *wsi)
{
	struct client_connection_info *client;

	list_for_each_entry(client, &connect_infos.clients, list)
		if (wsi == client->wsi)
			return client->state == CONNECTION_STATE_TEARINGDOWN;
	/* couldn't find the client??? this is wrong so close the connection */
	return true;
}

void wsubus_client_destroy(struct lws *wsi)
{
	struct client_connection_info *client, *tmp;

	list_for_each_entry_safe(client, tmp, &connect_infos.clients, list)
		if (wsi == client->wsi)
			wsubus_client_del(client);
}
