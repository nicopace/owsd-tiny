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

/*
 * dbus over websocket - dbus list
 */
#include "owsd-config.h"
#include "dbus_rpc_list.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"
#include "util_ubus_blob.h"
#include "dubus_conversions.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <dbus/dbus.h>
#include <libxml/parser.h>
#include <libwebsockets.h>

#include <assert.h>
#include <sys/types.h>
#include <regex.h>

struct wsd_call_ctx {
	union {
		struct ws_request_base;
		struct ws_request_base _base;
	};

	struct ubusrpc_blob *args;

	struct DBusMessage *list_reply;
	int reply_slot;

	struct DBusPendingCall *call_req;

	struct list_head introspectables;
};

struct introspection_target {
	char *service;
	char *path;
	struct list_head introspectables;
};

static void wsd_call_ctx_free(void *f)
{
	struct wsd_call_ctx *ctx = f;
	blob_buf_free(&ctx->retbuf);
	if (ctx->args) {
		free(ctx->args->src_blob);
		free(ctx->args);
	}
	free(ctx->id);

	if (ctx->reply_slot >= 0)
		dbus_message_free_data_slot(&ctx->reply_slot);
	free(ctx);
}

void wsd_call_ctx_cancel_and_destroy(struct ws_request_base *base)
{
	struct wsd_call_ctx *ctx = container_of(base, struct wsd_call_ctx, _base);
	dbus_pending_call_cancel(ctx->call_req);
	dbus_pending_call_unref(ctx->call_req);
	if (ctx->list_reply) {
		dbus_message_unref(ctx->list_reply);
	} else {
		wsd_call_ctx_free(ctx);
	}
}

static void wsd_introspect_cb(DBusPendingCall *call, void *data);

static void introspect_list_next(struct wsd_call_ctx *ctx)
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

static void introspect_list_finish(struct wsd_call_ctx *ctx)
{
	char *response_str = jsonrpc__resp_ubus(ctx->id, 0, ctx->retbuf.head);
	wsu_queue_write_str(ctx->wsi, response_str);
	free(response_str);
	dbus_message_unref(ctx->list_reply);
}

__attribute__((constructor)) static void _init(void)
{
}

__attribute__((destructor)) static void _dtor(void)
{
	xmlCleanupParser();
}

bool check_reply_and_make_error(DBusMessage *reply, const char *expected_signature, struct blob_buf *errordata)
{
	int type = dbus_message_get_type(reply);
	if (type == DBUS_MESSAGE_TYPE_ERROR) {
		if (errordata) {
			void *data_tkt = blobmsg_open_table(errordata, "data");
			blobmsg_add_string(errordata, "DBus", dbus_message_get_error_name(reply));
			char *datastr;
			if (dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &datastr))
				blobmsg_add_string(errordata, "text", datastr);
			blobmsg_close_table(errordata, data_tkt);
		}
		return false;
	}
	if (type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		return false;
	}
	if (expected_signature && strcmp(dbus_message_get_signature(reply), expected_signature)) {
		if (errordata) {
			void *data_tkt = blobmsg_open_table(errordata, "data");
			blobmsg_add_string(errordata, "DBus", DBUS_ERROR_INVALID_SIGNATURE);
			blobmsg_close_table(errordata, data_tkt);
		}
		return false;
	}
	return true;
}

static void wsd_introspect_cb(DBusPendingCall *call, void *data)
{
	struct wsd_call_ctx *ctx = data;

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

	void *p = NULL;

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
			continue; // TODO put this subnode in queue for later introspection
		} else if (xmlStrcmp(subnode->name, (xmlChar*)"interface") || sub_only) {
			// skip unknown node type
			continue;
		}

		if (!p)
			p = blobmsg_open_table(&ctx->retbuf, name);
		char *iface_name = (char*)xmlGetProp(subnode, (xmlChar*)"name");
		if (!iface_name)
			continue;

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

					//lwsl_warn("### %s   %-20s %s type=%s name=%s\n", is_signal ? "signal" : "method", m_name, arg_is_out ? "ret" : "arg", arg_type, arg_name ? arg_name : "?");

					xmlFree(arg_type);
					xmlFree(arg_name);
				}
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
		xmlFree(iface_name);
	}
	if (p)
		blobmsg_close_table(&ctx->retbuf, p);

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
	struct wsd_call_ctx *ctx = data;

	assert(ctx->call_req == call);
	dbus_pending_call_unref(ctx->call_req);
	ctx->call_req = NULL;

	blob_buf_init(&ctx->retbuf, 0);
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);

	ctx->list_reply = reply;
	dbus_message_allocate_data_slot(&ctx->reply_slot);
	dbus_message_set_data(ctx->list_reply, ctx->reply_slot, ctx, wsd_call_ctx_free);

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

void wsd_call_cb(struct DBusPendingCall *call, void *data)
{
	struct wsd_call_ctx *ctx = data;
	assert(ctx->call_req == call);
	dbus_pending_call_unref(ctx->call_req);
	ctx->call_req = NULL;

	list_del(&ctx->cq);

	blob_buf_init(&ctx->retbuf, 0);
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	assert(reply);

	if (!check_reply_and_make_error(reply, NULL, &ctx->retbuf)) {
		char *response_str = jsonrpc__resp_error(ctx->id, JSONRPC_ERRORCODE__OTHER, blobmsg_data(ctx->retbuf.head));
		wsu_queue_write_str(ctx->wsi, response_str);
		free(response_str);
		goto out;
	}

	void *tkt = blobmsg_open_array(&ctx->retbuf, dbus_message_get_signature(reply));

	DBusMessageIter iter;
	dbus_message_iter_init(reply, &iter);

	while (dbus_message_iter_get_arg_type(&iter)) {
		duconv_msg_dbus_to_ubus(&ctx->retbuf, &iter, "");
		dbus_message_iter_next(&iter);
	}

	blobmsg_close_array(&ctx->retbuf, tkt);

	char *response_str = jsonrpc__resp_ubus(ctx->id, 0, ctx->retbuf.head);
	wsu_queue_write_str(ctx->wsi, response_str);
	free(response_str);
out:
	dbus_message_unref(reply);
	wsd_call_ctx_free(ctx);
}

int ubusrpc_handle_dcall(struct lws *wsi, struct ubusrpc_blob *ubusrpc_blob, struct blob_attr *id)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	// blob_buf_free(ubusrpc_blob->call.params_buf);
	// blob_buf_init(ubusrpc_blob->call.params_buf, 0);

	char *dbus_service_name = duconv_name_ubus_to_dbus_name(ubusrpc_blob->call.object);
	if (!dbus_service_name) {
		lwsl_err("OOM\n");
		goto out;
	}

	if (!dbus_validate_bus_name(dbus_service_name, NULL)) {
		lwsl_warn("skip invalid name \n");
		free(dbus_service_name);
		goto out;
	}

	char *dbus_object_path = duconv_name_ubus_to_dbus_path(ubusrpc_blob->call.object);
	lwsl_info("making DBus call s=%s o=%s m=%s\n", dbus_service_name, dbus_object_path, ubusrpc_blob->call.method);
	DBusMessage *msg = dbus_message_new_method_call(dbus_service_name, dbus_object_path, dbus_service_name, ubusrpc_blob->call.method);
	free(dbus_object_path);
	free(dbus_service_name);

	if (!msg) {
		lwsl_warn("Failed to create message\n");
		goto out;
	}

	DBusMessageIter arg_iter;
	dbus_message_iter_init_append(msg, &arg_iter);
	struct blob_attr *cur_arg;
	unsigned int rem = 0;
	blob_for_each_attr(cur_arg, ubusrpc_blob->call.params_buf->head, rem) {
		int dbus_type = duconv_msg_ubus_to_dbus(&arg_iter, cur_arg, NULL);
		if (dbus_type == DBUS_TYPE_INVALID) {
			lwsl_warn("Can not convert argument name=%s type=%d for DBus call %s %s\n", blobmsg_name(cur_arg), blobmsg_type(cur_arg), ubusrpc_blob->call.object, ubusrpc_blob->call.method);
			goto out2;
		}
	}

	DBusPendingCall *call;
	if (!dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, DBUS_TIMEOUT_USE_DEFAULT)) {
		goto out2;
	}

	struct wsd_call_ctx *ctx = calloc(1, sizeof *ctx);
	if (!ctx) {
		lwsl_err("OOM ctx\n");
		goto out3;
	}

	ctx->wsi = wsi;
	ctx->id = id ? blob_memdup(id) : NULL;
	ctx->cancel_and_destroy = wsd_call_ctx_cancel_and_destroy;
	ctx->call_req = call;
	ctx->args = ubusrpc_blob;
	if (id && !ctx->id) {
		lwsl_err("OOM ctx id\n");
		goto out4;
	}
	ctx->reply_slot = -1;

	dbus_message_unref(msg);

	blob_buf_free(ubusrpc_blob->call.params_buf);
	free(ubusrpc_blob->call.params_buf);
	ubusrpc_blob->call.params_buf = NULL;

	if (!dbus_pending_call_set_notify(call, wsd_call_cb, ctx, NULL) || !call) {
		lwsl_err("failed to set notify callback\n");
		goto out5;
	}
	lwsl_debug("dbus-calling %p %p\n", call, ctx);

	struct wsu_client_session *client = wsi_to_client(wsi);
	list_add_tail(&ctx->cq, &client->rpc_call_q);

	return 0;

out5:
	free(ctx->id);
out4:
	free(ctx);
out3:
	dbus_pending_call_unref(call);
out2:
	dbus_message_unref(msg);
out:
	free(ubusrpc_blob->list.src_blob);

	if (ubusrpc_blob->call.params_buf) {
		blob_buf_free(ubusrpc_blob->call.params_buf);
		free(ubusrpc_blob->call.params_buf);
		ubusrpc_blob->call.params_buf = NULL;
	}

	return -1;
}

int ubusrpc_handle_dlist(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	DBusMessage *msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "ListNames");
	if (!msg) {
		goto out;
	}

	DBusPendingCall *call;
	if (!dbus_connection_send_with_reply(prog->dbus_ctx, msg, &call, DBUS_TIMEOUT_USE_DEFAULT) || !call) {
		goto out2;
	}

	struct wsd_call_ctx *ctx = calloc(1, sizeof *ctx);
	if (!ctx) {
		goto out3;
	}
	ctx->wsi = wsi;
	ctx->id = id ? blob_memdup(id) : NULL;
	ctx->cancel_and_destroy = wsd_call_ctx_cancel_and_destroy;
	ctx->call_req = call;
	ctx->args = ubusrpc;
	if (id && !ctx->id) {
		goto out4;
	}
	ctx->reply_slot = -1;

	if (!dbus_pending_call_set_notify(call, wsd_list_cb, ctx, NULL)) {
		goto out5;
	}

	dbus_message_unref(msg);

	return 0;

out5:
	free(ctx->id);
out4:
	free(ctx);
out3:
	dbus_pending_call_unref(call);
out2:
	dbus_message_unref(msg);
out:
	free(ubusrpc->list.src_blob);
	return -1;
}

