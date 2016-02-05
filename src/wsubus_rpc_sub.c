/*
 * ubus over websocket - ubus event subscription
 */
#include "wsubus_rpc_sub.h"

#include "common.h"
#include "wsubus.impl.h"
#include "wsubus_rpc.h"

#include <libubox/blobmsg.h>
#include <libubus.h>

#include <libwebsockets.h>

int ubusrpc_blob_sub_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	struct blobmsg_policy sub_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING }
	};

	struct blob_attr *tb_name;

	blobmsg_parse_array(sub_policy, ARRAY_SIZE(sub_policy), &tb_name, blobmsg_data(blob), blobmsg_len(blob));

	if (!tb_name) {
		return -1;
	}
	
	const char *name = blobmsg_get_string(tb_name);

	ubusrpc->sub.src_blob = NULL;
	ubusrpc->sub.objname = name;

	return 0;
}

static void wsubus_sub_cb(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg);

int ubusrpc_handle_sub(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct ubusrpc_blob_sub sub_req = ubusrpc->sub;

	struct prog_context *prog = lws_context_user(lws_get_context(wsi));

	int ret;

	struct ubus_event_handler *sub = calloc(1, sizeof *sub);
	if (!sub) {
		lwsl_err("failed to alloc ubus sub\n");
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	sub->cb = wsubus_sub_cb;

	// TODO track which client is subscribed to which obj,

	ret = ubus_register_event_handler(prog->ubus_ctx, sub, sub_req.objname);

	lwsl_info("ubus subscribe to %s = %s\n", sub_req.objname, ubus_strerror(ret));

	char *response;
out:
	response = jsonrpc_response_from_blob(id, ret, NULL);
	wsubus_write_response_str(wsi, response);
	free(response);

	return 0;
}

static void wsubus_sub_cb(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg)
{
	int mtype = blobmsg_type(msg);
	lwsl_debug("sub cb called, ev obj name %s, type %s, blob of len %lu thpe %s\n",
			ev->obj.name, type, blobmsg_len(msg),
			mtype == BLOBMSG_TYPE_STRING ? "\"\"" :
			mtype == BLOBMSG_TYPE_TABLE ? "{}" :
			mtype == BLOBMSG_TYPE_ARRAY ? "[]" : "<>");

	// TODO sohehow get to context and from there find out which clients are
	// subscribed to this event, and notify them over websocket
	// 0. find client in subscribers of ev (first version search linear is OK,
	// then can use avl_ functions from libubox
	// 1. make blob/json of response for this event
	//char *response; // ...;
	// 2. write to client
	//wsubus_write_response_str(wsi, response);


}
