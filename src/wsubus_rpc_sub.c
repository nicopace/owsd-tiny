/*
 * ubus over websocket - ubus event subscription
 */

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubus.h>

#include <libwebsockets.h>

#include "common.h"
#include "wsubus.impl.h"
#include "wsubus_rpc.h"

struct wsubus_sub_info {
	uint32_t sub_id;

	struct list_head list;

	struct blob_attr *src_blob;
	const char *sid;
	const char *pattern;

	struct ubus_event_handler ubus_handler;

	struct lws *wsi;
};

static struct wsubus_sub_info list_of_subscriptions = { .list = LIST_HEAD_INIT(list_of_subscriptions.list) };

static void wsubus_sub_cb(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg);

static void wsubus_unsub_elem(struct wsubus_sub_info *elem)
{
	struct prog_context *prog = lws_context_user(lws_get_context(elem->wsi));
	ubus_unregister_event_handler(prog->ubus_ctx, &elem->ubus_handler);
	free(elem->src_blob);
	list_del(&elem->list);
	free(elem);
}

void wsubus_unsubscribe_all()
{
	int count = 0;
	struct wsubus_sub_info *elem, *tmp;

	list_for_each_entry_safe(elem, tmp, &list_of_subscriptions.list, list) {
		lwsl_warn("cleanall %s\n", elem->sid);
		wsubus_unsub_elem(elem);
		elem = NULL;
		++count;
	}
	if (count)
		lwsl_warn("%d subscriptions cleaned at exit\n", count);
}

int wsubus_unsubscribe_by_id(uint32_t id)
{
	struct wsubus_sub_info *elem, *tmp;
	int ret = 1;

	list_for_each_entry_safe(elem, tmp, &list_of_subscriptions.list, list) {
		// check id
		if (elem->sub_id == id) {
			wsubus_unsub_elem(elem);
			ret = 0;
		}
	}
	return ret;
}

int wsubus_unsubscribe_by_sid_pattern(const char *sid, const char *pattern)
{
	struct wsubus_sub_info *elem, *tmp;
	int ret = 1;

	list_for_each_entry_safe(elem, tmp, &list_of_subscriptions.list, list) {
		// check sid, pattern
		if (!strcmp(elem->sid, sid) && !strcmp(pattern, elem->pattern)) {
			wsubus_unsub_elem(elem);
			elem = NULL;
			ret = 0;
		}
	}
	return ret;
}

int wsubus_unsubscribe_all_by_sid(const char *sid)
{
	struct wsubus_sub_info *elem, *tmp;
	int ret = 1;

	list_for_each_entry_safe(elem, tmp, &list_of_subscriptions.list, list) {
		// check sid
		if (!strcmp(elem->sid, sid)) {
			lwsl_warn("cleansub %s\n", elem->sid);
			wsubus_unsub_elem(elem);
			elem = NULL;
			ret = 0;
		}
	}
	return ret;
}

int ubusrpc_blob_sub_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // ubus-object
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	struct blob_attr *dup_blob = blob_memdup(blob);
	if (!dup_blob) {
		return -100;
	}

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blobmsg_data for blob which
	// comes from another blob's table... here and so do we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb, blobmsg_data(dup_blob), blobmsg_len(dup_blob));

	if (!tb[0])
		return -1;
	if (!tb[1])
		return -2;

	ubusrpc->sub.src_blob = dup_blob;
	ubusrpc->sub.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->sub.object = blobmsg_get_string(tb[1]);

	return 0;
}

int ubusrpc_blob_sub_list_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blobmsg_data for blob which
	// comes from another blob's table... here and so do we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb, blobmsg_data(blob), blobmsg_len(blob));

	if (!tb[0])
		return 2;

	ubusrpc->sub.src_blob = NULL;
	ubusrpc->sub.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;

	return 0;
}

int ubusrpc_blob_unsub_by_id_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_INT32 }, // subscribe id
	};
	enum { __RPC_U_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_U_MAX];

	// TODO<blob> blob_(data|len) vs blobmsg_xxx usage, what is the difference
	// and which is right here? (uhttpd ubus uses blobmsg_data for blob which
	// comes from another blob's table... here and so do we)
	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_U_MAX, tb, blobmsg_data(blob), blobmsg_len(blob));

	if (!tb[0])
		return 2;
	if (!tb[1])
		return 2;

	ubusrpc->unsub_by_id.src_blob = NULL;
	ubusrpc->unsub_by_id.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->unsub_by_id.id = blobmsg_get_u32(tb[1]);

	return 0;
}


int ubusrpc_handle_sub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	static uint32_t subscribe_id = 1;

	int ret;

	struct wsubus_sub_info *subinfo = malloc(sizeof *subinfo);
	if (!subinfo) {
		lwsl_err("alloc subinfo error\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	if (wsubus_check_and_update_sid(client, ubusrpc->sub.sid) != 0) {
		lwsl_warn("curr sid %s != prev sid %s\n", ubusrpc->sub.sid, client->last_known_sid);
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto out;
	}

	subinfo->ubus_handler = (struct ubus_event_handler){};

	ret = ubus_register_event_handler(prog->ubus_ctx, &subinfo->ubus_handler, ubusrpc->sub.object);

	if (ret) {
		lwsl_err("ubus reg evh error %s\n", ubus_strerror(ret));
		// free memory
		goto out;
	}

	subinfo->ubus_handler.cb = wsubus_sub_cb;

	subinfo->sub_id = subscribe_id++;
	subinfo->src_blob = ubusrpc->sub.src_blob;
	subinfo->sid = ubusrpc->sub.sid;
	subinfo->pattern = ubusrpc->sub.object;
	// subinfo->ubus_handler inited above in ubus_register_...
	subinfo->wsi = wsi;

	ubusrpc->src_blob = NULL;

	list_add_tail(&subinfo->list, &list_of_subscriptions.list);

out:
	if (ret) {
		free(ubusrpc->sub.src_blob);
		ubusrpc->src_blob = NULL;
	}
	char *response = jsonrpc_response_from_blob(id, ret, NULL);
	wsubus_write_response_str(wsi, response);
	free(response);
	free(ubusrpc);

	return 0;
}

static void blobmsg_add_sub_info(struct blob_buf *buf, const char *name, const struct wsubus_sub_info *sub)
{
	void *tkt = blobmsg_open_table(buf, name);

	blobmsg_add_string(buf, "pattern", sub->pattern);
	blobmsg_add_u32(buf, "id", sub->sub_id);
	blobmsg_add_string(buf, "ubus_rpc_session", sub->sid);

	blobmsg_close_table(buf, tkt);
}

int ubusrpc_handle_sub_list(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct blob_buf b = {};
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "jsonrpc", "2.0");
	blobmsg_add_blob(&b, id);

#if 0 // TODO
	struct wsubus_client_session *client = lws_wsi_user(wsi);

	if (wsubus_check_and_update_sid(client, ubusrpc->sub.sid) != 0) {
		lwsl_warn("curr sid %s != prev sid %s\n", ubusrpc->sub.sid, client->last_known_sid);
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto out;
	}
#endif

	void *array_ticket = blobmsg_open_array(&b, "result");
	struct wsubus_sub_info *elem, *tmp;
	list_for_each_entry_safe(elem, tmp, &list_of_subscriptions.list, list) {
		blobmsg_add_sub_info(&b, "", elem);
	}
	blobmsg_close_array(&b, array_ticket);

	char *json_data = blobmsg_format_json(b.head, true);

	blob_buf_free(&b);

	wsubus_write_response_str(wsi, json_data);

	// free memory
	free(json_data);
	free(ubusrpc->sub.src_blob);
	free(ubusrpc);
	return 0;
}

int ubusrpc_handle_unsub_by_id(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	char *response;
	int ret = 0;

	struct wsubus_client_session *client = lws_wsi_user(wsi);

	if (wsubus_check_and_update_sid(client, ubusrpc->sub.sid) != 0) {
		lwsl_warn("curr sid %s != prev sid %s\n", ubusrpc->sub.sid, client->last_known_sid);
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto out;
	}

	lwsl_debug("unsub by id %u ret = %d\n", ubusrpc->unsub_by_id.id, ret);
	ret = wsubus_unsubscribe_by_id(ubusrpc->unsub_by_id.id);

	if (ret != 0)
		ret = UBUS_STATUS_NOT_FOUND;

out:
	response = jsonrpc_response_from_blob(id, ret, NULL);
	wsubus_write_response_str(wsi, response);
	free(response);
	free(ubusrpc);

	return 0;
}

static void wsubus_sub_cb(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg)
{
	struct wsubus_sub_info *sub = container_of(ev, struct wsubus_sub_info, ubus_handler);

	__attribute__((unused)) int mtype = blobmsg_type(msg);
	lwsl_debug("sub cb called, ev obj name %s, type %s, blob of len %lu thpe %s\n",
			ev->obj.name, type, blobmsg_len(msg),
			mtype == BLOBMSG_TYPE_STRING ? "\"\"" :
			mtype == BLOBMSG_TYPE_TABLE ? "{}" :
			mtype == BLOBMSG_TYPE_ARRAY ? "[]" : "<>");

	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);
	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	blobmsg_add_string(&resp_buf, "method", "event");

	void *tkt = blobmsg_open_table(&resp_buf, "params");
	blobmsg_add_string(&resp_buf, "type", type);
	blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_TABLE, "data", blobmsg_data(msg), blobmsg_len(msg));
	blobmsg_add_sub_info(&resp_buf, "subscription", sub);
	blobmsg_close_table(&resp_buf, tkt);

	char *response = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);

	wsubus_write_response_str(sub->wsi, response);
	free(response);
}
