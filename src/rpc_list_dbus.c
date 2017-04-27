/*
 * Copyright (C) 2017 Inteno Broadband Technology AB. All rights reserved.
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

/*
 * dbus over websocket - dbus list
 */
#include "owsd-config.h"
#include "rpc_list_dbus.h"
#include "rpc_list.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"
#include "util_dbus.h"
#include "dubus_conversions.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <dbus/dbus.h>
#include <libxml/parser.h>
#include <libwebsockets.h>

#include <assert.h>
#include <sys/types.h>
#include <regex.h>

struct introspection_target {
	char *service;
	char *path;
	struct list_head introspectables;
};

static void wsd_list_ctx_free(void *f)
{
	struct wsd_list_ctx *ctx = f;
	blob_buf_free(&ctx->retbuf);
	free(ctx->id);

	if (ctx->reply_slot >= 0)
		dbus_message_free_data_slot(&ctx->reply_slot);
	free(ctx);
}

void wsd_list_ctx_cancel_and_destroy(struct ws_request_base *base)
{
	struct wsd_list_ctx *ctx = container_of(base, struct wsd_list_ctx, _base);
	if (ctx->call_req) {
		dbus_pending_call_cancel(ctx->call_req);
		dbus_pending_call_unref(ctx->call_req);
	}

	while (!list_empty(&ctx->introspectables)) {
		struct introspection_target *cur = list_first_entry(&ctx->introspectables, struct introspection_target, introspectables);
		list_del(&cur->introspectables);
		free(cur->service);
		free(cur->path);
		free(cur);
	}
	if (ctx->list_reply) {
		dbus_message_unref(ctx->list_reply);
	} else {
		wsd_list_ctx_free(ctx);
	}
}

static void wsd_introspect_cb(DBusPendingCall *call, void *data);

static void introspect_list_next(struct wsd_list_ctx *ctx)
{
	struct prog_context *prog = lws_context_user(lws_get_context(ctx->wsi));
	struct introspection_target *cur = list_first_entry(&ctx->introspectables, struct introspection_target, introspectables);

	DBusMessage *introspect = dbus_message_new_method_call(cur->service, cur->path, DBUS_INTERFACE_INTROSPECTABLE, "Introspect");
	DBusPendingCall *introspect_call;
	dbus_connection_send_with_reply(prog->dbus_ctx, introspect, &introspect_call, 1000);
	dbus_pending_call_set_notify(introspect_call, wsd_introspect_cb, ctx, NULL);

	assert(!ctx->call_req);
	ctx->call_req = introspect_call;
	dbus_message_unref(introspect);
}

static void introspect_list_finish(struct wsd_list_ctx *ctx)
{
	char *response_str = jsonrpc__resp_ubus(ctx->id, 0, ctx->retbuf.head);
	wsu_queue_write_str(ctx->wsi, response_str);
	free(response_str);
	list_del(&ctx->cq);
	dbus_message_unref(ctx->list_reply);
}

__attribute__((constructor)) static void _init(void)
{
}

__attribute__((destructor)) static void _dtor(void)
{
	xmlCleanupParser();
}

static void wsd_introspect_cb(DBusPendingCall *call, void *data)
{
	struct wsd_list_ctx *ctx = data;

	assert(ctx->call_req == call);
	dbus_pending_call_unref(ctx->call_req);
	ctx->call_req = NULL;

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);

	struct introspection_target *cur = list_first_entry(&ctx->introspectables, struct introspection_target, introspectables);
	char *name = duconv_name_dbus_path_to_ubus(cur->path);

	bool sub_only = false;
	if (!name) {
		sub_only = true;
		// TODO
	}
	if (!check_reply_and_make_error(reply, "s", NULL)) {
		lwsl_warn("DBus Introspected svc %s obj %s with error, skipping\n", cur->service, cur->path);
		// we ignore the error and skip this service
		goto next_service;
	}

	lwsl_debug("DBus Introspected svc %s obj %s\n", cur->service, cur->path);

	const char *xml;
	dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &xml);
	size_t xml_len = strlen(xml);
	xmlDoc *xml_doc = xmlParseMemory(xml, xml_len);

	xmlNode *xml_root = xmlDocGetRootElement(xml_doc);

	if (xml_root->type != XML_ELEMENT_NODE || xmlStrcmp(xml_root->name, (xmlChar*)"node") || !xml_root->children) {
		goto next_service_xml;
	}

	for (xmlNode *subnode = xml_root->children; subnode; subnode = subnode->next) {
		if (subnode->type != XML_ELEMENT_NODE)
			continue;

		if (!xmlStrcmp(subnode->name, (xmlChar*)"node")) {
			char *node_name = (char*)xmlGetProp(subnode, (xmlChar*)"name");
			if (!node_name)
				continue;

			struct introspection_target *new = malloc(sizeof *new);
			new->service = strdup(cur->service);
			size_t new_path_len = strlen(cur->path) + 2 + strlen(node_name);
			new->path = malloc(new_path_len);
			new->path[0] = '\0';
			strcat(new->path, cur->path);
			if (new->path[strlen(new->path)-1] != '/')
				strcat(new->path, "/");
			strcat(new->path, node_name);
			list_add_tail(&new->introspectables, &ctx->introspectables);
			lwsl_debug("DBus Introspecting later svc %s obj %s\n", new->service, new->path);

			xmlFree(node_name);
			continue;
		} else if (xmlStrcmp(subnode->name, (xmlChar*)"interface") || sub_only) {
			// skip unknown node type
			continue;
		}

		char *iface_name = (char*)xmlGetProp(subnode, (xmlChar*)"name");
		if (!iface_name)
			continue;

		void *p = NULL;
		char *_name = duconv_name_dbus_name_to_ubus(iface_name);
		if (_name && !strcmp(_name, name))
			p = blobmsg_open_table(&ctx->retbuf, name);
		if (_name)
			free(_name);

		if (!p)
			goto next_iface;

		for (xmlNode *member = subnode->children; member; member = member->next) {
			if (member->type != XML_ELEMENT_NODE)
				continue;

			bool is_method = !xmlStrcmp(member->name, (xmlChar*)"method");
			bool is_signal = !xmlStrcmp(member->name, (xmlChar*)"signal");
			bool is_property = !xmlStrcmp(member->name, (xmlChar*)"property");

			if (!is_method && !is_signal && !is_property)
				continue;

			char *m_name = (char*)xmlGetProp(member, (xmlChar*)"name");
			if (!m_name)
				continue;

			if (is_method || is_signal) {
				void *q = NULL;
				for (xmlNode *arg = member->children; arg; arg = arg->next) {
					if (member->type != XML_ELEMENT_NODE || xmlStrcmp(arg->name, (xmlChar*)"arg"))
						continue;

					char *arg_type = (char*)xmlGetProp(arg, (xmlChar*)"type");
					if (!arg_type)
						continue;

					char *arg_name = (char*)xmlGetProp(arg, (xmlChar*)"name");
					bool arg_is_out = false;

					xmlChar *arg_dir = xmlGetProp(arg, (xmlChar*)"direction");
					if (is_method && arg_dir) {
						arg_is_out = !xmlStrcmp(arg_dir, (xmlChar*)"out");
						xmlFree(arg_dir);
					}

					if (is_method && !q) {
						q = blobmsg_open_table(&ctx->retbuf, m_name);
					}
					if (q && !arg_is_out) {
						int ubus_type = duconv_type_dbus_to_ubus(arg_type[0], arg_type[1]);
						const char *typestr = blobmsg_type_to_str(ubus_type);
						typestr = typestr ? typestr : "unknown";
						blobmsg_add_string(&ctx->retbuf, arg_name, typestr);
					}

					//lwsl_warn("### %s   %-20s %s type=%s name=%s\n", is_signal ? "signal" : "method", m_name, arg_is_out ? "ret" : "arg", arg_type, arg_name ? arg_name : "?");

					xmlFree(arg_type);
					xmlFree(arg_name);
				}
				if (q)
					blobmsg_close_table(&ctx->retbuf, q);
			} else if (is_property) {
				char *m_type = (char*)xmlGetProp(member, (xmlChar*)"type");
				if (!m_type) {
					goto next_member;
				}

				xmlChar *m_access = xmlGetProp(member, (xmlChar*)"access");
				if (!m_access) {
					xmlFree(m_type);
					goto next_member;
				} else if (!xmlStrcmp(m_access, (xmlChar*)"read")) {
				} else if (!xmlStrcmp(m_access, (xmlChar*)"readwrite")) {
				} else if (!xmlStrcmp(m_access, (xmlChar*)"write")) {
				} else {
				}

				//lwsl_warn("### property %-20s type=%s\n", m_name, m_type);

				xmlFree(m_access);
				xmlFree(m_type);
			}

		next_member:
			xmlFree(m_name);
		}

	next_iface:
		if (p)
			blobmsg_close_table(&ctx->retbuf, p);

		xmlFree(iface_name);
	}

next_service_xml:
	xmlFreeDoc(xml_doc);

next_service:
	list_del(&cur->introspectables);
	free(cur->service);
	free(cur->path);
	free(cur);
	if (!list_empty(&ctx->introspectables)) {
		introspect_list_next(ctx);
	} else {
		introspect_list_finish(ctx);
	}

	free(name);
	dbus_message_unref(reply);
}

static void wsd_list_cb(DBusPendingCall *call, void *data)
{
	struct wsd_list_ctx *ctx = data;

	assert(ctx->call_req == call);
	dbus_pending_call_unref(ctx->call_req);
	ctx->call_req = NULL;

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);

	ctx->list_reply = reply;
	dbus_message_allocate_data_slot(&ctx->reply_slot);
	dbus_message_set_data(ctx->list_reply, ctx->reply_slot, ctx, wsd_list_ctx_free);

	if (!check_reply_and_make_error(reply, "as", &ctx->retbuf)) {
		char *response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__OTHER, blobmsg_data(ctx->retbuf.head));
		wsu_queue_write_str(ctx->wsi, response_str);
		free(response_str);
		dbus_message_unref(reply);
		return;
	}

	DBusMessageIter resp_iter, arr_iter;
	dbus_message_iter_init(reply, &resp_iter);
	dbus_message_iter_recurse(&resp_iter, &arr_iter);
	INIT_LIST_HEAD(&ctx->introspectables);
	while (dbus_message_iter_get_arg_type(&arr_iter) != DBUS_TYPE_INVALID) {
		struct introspection_target *new = malloc(sizeof *new);
		dbus_message_iter_get_basic(&arr_iter, &new->service);

		if (new->service[0] == ':') {
			dbus_message_iter_next(&arr_iter);
			free(new);
			continue;
		}

		new->service = strdup(new->service);
		new->path = strdup(WSD_DBUS_OBJECTS_PATH);
		list_add_tail(&new->introspectables, &ctx->introspectables);
		dbus_message_iter_next(&arr_iter);
	}

	if (!list_empty(&ctx->introspectables)) {
		introspect_list_next(ctx);
	} else {
		introspect_list_finish(ctx);
	}

	return;
}

int handle_list_dbus(struct ws_request_base *req, struct lws *wsi, struct ubusrpc_blob *ubusrpc_, struct blob_attr *id)
{
	struct ubusrpc_blob_list *ubusrpc = container_of(ubusrpc_, struct ubusrpc_blob_list, _base);
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	DBusMessage *msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "ListNames");
	if (!msg) {
		goto out;
	}

	DBusPendingCall *call;
	if (!dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, DBUS_TIMEOUT_USE_DEFAULT) || !call) {
		goto out2;
	}

	struct wsd_list_ctx *ctx = container_of(req, struct wsd_list_ctx, _base);
	ctx->call_req = call;
	ctx->reply_slot = -1;
	ubusrpc_blob_destroy_default(&ubusrpc->_base);

	if (!dbus_pending_call_set_notify(call, wsd_list_cb, ctx, NULL)) {
		goto out3;
	}

	dbus_message_unref(msg);

	struct wsu_client_session *client = wsi_to_client(wsi);
	list_add_tail(&ctx->cq, &client->rpc_call_q);

	return 0;

out3:
	dbus_pending_call_unref(call);
out2:
	dbus_message_unref(msg);
out:
	free(ubusrpc->src_blob);
	return -1;
}

