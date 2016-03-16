/*
 * Copyright (C) 2016 Inteno Broadband Technology AB
 *
 * This software is the confidential and proprietary information of the
 * Inteno Broadband Technology AB. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the
 * license agreement you entered into with the Inteno Broadband Technology AB
 *
 * All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 */
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

	unsigned char *buf = malloc(LWS_SEND_BUFFER_PRE_PADDING
			+ len
			+ LWS_SEND_BUFFER_POST_PADDING);
	if (!buf) {
		lwsl_err("failed to alloc ubus response buf");
		return -2;
	}

	memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, response_str, len);

	struct wsubus_client_session *client = lws_wsi_user(wsi);

	struct wsubus_client_writereq *w = malloc(sizeof *w);
	w->buf = buf;
	w->len = len;
	w->written = 0;

	list_add_tail(&w->wq, &client->write_q);

	lwsl_debug("sending reply: %.*s ... %p, %d\n", len > 50 ? 50 : len, response_str, w);
	int r = lws_callback_on_writable(wsi);

	if (r < 0) {
		lwsl_warn("error %d scheduling write callback\n");
		return -3;
	}

	return 0;
}

int wsubus_check_and_update_sid(struct wsubus_client_session *client, const char *sid)
{
	if (client->last_known_sid == NULL) {
		client->last_known_sid = strdup(sid);
		return 0;
	}
	if (!strcmp(client->last_known_sid, UBUS_DEFAULT_SID)) {
		free(client->last_known_sid);
		client->last_known_sid = strdup(sid);
		return 0;
	}

	if (strcmp(client->last_known_sid, sid)) {
		lwsl_warn("curr sid %s != prev sid %s\n", sid, client->last_known_sid);
		return 1;
	}
	return 0;
}
