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
#include "util_jsonrpc.h"
#include <libubox/blobmsg_json.h>

char* jsonrpc__resp_error(struct blob_attr *id, int error_code, struct blob_attr *error_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *obj_ticket = blobmsg_open_table(&resp_buf, "error");

	blobmsg_add_u32(&resp_buf, "code", (uint32_t)error_code);
	blobmsg_add_string(&resp_buf, "message",
			error_code == JSONRPC_ERRORCODE__PARSE_ERROR      ? "Parse error" :
			error_code == JSONRPC_ERRORCODE__INTERNAL_ERROR   ? "Internal error" :
			error_code == JSONRPC_ERRORCODE__INVALID_REQUEST  ? "Invalid Request" :
			error_code == JSONRPC_ERRORCODE__INVALID_PARAMS   ? "Invalid params" :
			error_code == JSONRPC_ERRORCODE__METHOD_NOT_FOUND ? "Method not found" :
			"Other error");
	if (error_data && !strcmp("data", blobmsg_name(error_data)))
		blobmsg_add_blob(&resp_buf, error_data);

	blobmsg_close_table(&resp_buf, obj_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}

char* jsonrpc__resp_ubus(struct blob_attr *id, int ubus_rc, struct blob_attr *ret_data)
{
	struct blob_buf resp_buf = {};
	blob_buf_init(&resp_buf, 0);

	blobmsg_add_string(&resp_buf, "jsonrpc", "2.0");
	if (id) {
		blobmsg_add_blob(&resp_buf, id);
	} else {
		// this works out to null in json
		blobmsg_add_field(&resp_buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
	}

	void *array_ticket = blobmsg_open_array(&resp_buf, "result");
	blobmsg_add_u32(&resp_buf, "", (uint32_t)ubus_rc);

	if (ret_data) {
		blobmsg_add_field(&resp_buf, blobmsg_type(ret_data) == BLOBMSG_TYPE_ARRAY ? BLOBMSG_TYPE_ARRAY : BLOBMSG_TYPE_TABLE, "", blobmsg_data(ret_data), (unsigned)blobmsg_len(ret_data));
	}

	blobmsg_close_array(&resp_buf, array_ticket);

	char *ret = blobmsg_format_json(resp_buf.head, true);
	blob_buf_free(&resp_buf);
	return ret;
}

char *jsonrpc__req_ubuslist(int id, const char *sid, const char *pattern)
{
	static char buf[2048];
	// TODO use json_object, blobmsg or handle (malicions) escapes in the printf
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"list\","
			"\"params\":[\"%s\", \"%s\"]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			pattern);
	return buf;
}

char *jsonrpc__req_ubuslisten(int id, const char *sid, const char *pattern)
{
	static char buf[2048];
	// TODO use json_object, blobmsg or handle (malicions) escapes in the printf
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"subscribe\","
			"\"params\":[\"%s\", \"%s\"]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			pattern);
	return buf;
}

char *jsonrpc__req_ubuscall(int id, const char *sid, const char *obj, const char *method, json_object *arg)
{
	static char buf[2048];
	// TODO use json_object, blobmsg or handle (malicions) escapes in the printf
	// XXX FIXME
	snprintf(buf, sizeof buf, "{"
			"\"jsonrpc\":\"2.0\",\"id\":%d,"
			"\"method\":\"call\","
			"\"params\":[\"%s\", \"%s\", \"%s\", %s]"
			"}",
			id,
			sid ? sid : "00000000000000000000000000000000",
			obj, method, arg ? json_object_to_json_string(arg) : "{}");
	return buf;
}
