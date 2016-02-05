/*
 * ubus over websocket - used to implement individual rpc methods
 */
#include "wsubus.impl.h"

#include <libubox/blobmsg.h>
#include <libwebsockets.h>

#include <assert.h>

int wsubus_write_response_str(struct lws *wsi, const char *response_str)
{
	if (!response_str) {
		lwsl_err("Not writing null message\n");
		return -1;
	}

	size_t len = strlen(response_str);

	assert(len < WSUBUS_MAX_MESSAGE_LEN);

	lwsl_debug("sending reply: %.*s ...\n", len > 50 ? 50 : len, response_str);

	unsigned char *buf = malloc(LWS_SEND_BUFFER_PRE_PADDING
			+ len
			+ LWS_SEND_BUFFER_POST_PADDING);
	if (!buf) {
		lwsl_err("failed to alloc ubus response buf");
		return -2;
	}

	memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, response_str, len);

	int written = lws_write(wsi, buf+LWS_SEND_BUFFER_PRE_PADDING, len,
			LWS_WRITE_TEXT);

	while (written != (int)len) {
		lwsl_debug("Partial write, repeating\n");
		written += lws_write(wsi,
				buf+LWS_SEND_BUFFER_PRE_PADDING+written, len-written,
				LWS_WRITE_TEXT);
	}

	free(buf);
	return 0;
	//TODO<blockingwrite> use callback and queue writes
	// like this
	// 1. put response_str,len in queue per-wsi context or globally
	// 2. request that lws calls us when we can write
	lws_callback_on_writable(wsi);
	// 3. handle LWS_ON_WRITABLE callback in wsubus.c cb, writing from queue
}

void wsubus_client_call_reset(struct wsubus_client_session *client)
{
	free(client->curr_call.retdata);
	client->curr_call.retdata = NULL;

	free(client->curr_call.id);
	client->curr_call.id = NULL;

	free(client->curr_call.call_args->src_blob);
	client->curr_call.call_args->src_blob = NULL;

	blob_buf_free(client->curr_call.call_args->params_buf);
	free(client->curr_call.call_args->params_buf);
	client->curr_call.call_args->params_buf = NULL;

	free(client->curr_call.call_args);
	client->curr_call.call_args = NULL;

	// we don't free these, the requests free themselves
	if (client->curr_call.invoke_req) {
		assert(client->curr_call.state == WSUBUS_CALL_STATE_CALL || client->curr_call.state == WSUBUS_CALL_STATE_CHECK);
		client->curr_call.invoke_req = NULL;
	}
	client->curr_call.state = WSUBUS_CALL_STATE_READY;
}

