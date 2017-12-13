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

/* add a string to a json array-object */
static int custom_json_object_array_add_string(struct json_object *array,
						const char *val)
{
	int rv;
	struct json_object *jo;

	if (!json_object_is_type(array, json_type_array))
		goto fail;

	jo = json_object_new_string(val);
	if (!jo)
		goto fail;

	rv = json_object_array_add(array, jo);
	if (rv) {
		json_object_put(jo);
		goto fail;
	}

	return 0;

fail:
	return -1;
}

/*
 * Prepare a json like: (then make it a string)
 * {
 *	"jsonrpc":"2.0",
 *	"id":$id,
 *	"method":"call",
 *	"params":[ "$sid", "$obj", "$method", "$arg" ]
 * }
 * {
 *	"jsonrpc":"2.0",
 *	"id":$id,
 *	"method":"subscribe/list",
 *	"params":[ "$sid", "$pattern" ]
 * }
 *
 * "method" option is set from $jsonrpc_method.
 * $jsonrpc_method can be: "call", "subscribe", "list"
 *
 * Note: this functions allocates memory, remember to free it
 */
static char *jsonrpc__req_to_string(
		int id, const char *sid, const char *jsonrpc_method,
		const char *obj, const char *method, json_object *arg,
		const char *pattern)
{
	int rv;
	struct json_object *jo;
	struct json_object *jo_version, *jo_id, *jo_method;
	struct json_object *jo_params, *jo_arg = NULL;
	const char *jstring;
	char *string = NULL;

	jo = json_object_new_object();
	if (!jo)
		goto out;

	/* create json object for version */
	jo_version = json_object_new_string("2.0");
	if (!jo_version)
		goto out_jo;
	json_object_object_add(jo, "jsonrpc", jo_version);

	/* create json object for id */
	jo_id = json_object_new_int64(id);
	if (!jo_id)
		goto out_jo;
	json_object_object_add(jo, "id", jo_id);

	/* create json object for method */
	jo_method = json_object_new_string(jsonrpc_method);
	if (!jo_method)
		goto out_jo;
	json_object_object_add(jo, "method", jo_method);

	/* create json object for params array */
	jo_params = json_object_new_array();
	if (!jo_params)
		goto out_jo;

	/* fill in the params array */
	rv = custom_json_object_array_add_string(jo_params,
			sid ? sid : "00000000000000000000000000000000");
	if (rv)
		goto out_jo_params;

	if (strcmp(jsonrpc_method, "call") == 0) {
		/* prepare the params array for a ubus "call" */

		rv = custom_json_object_array_add_string(jo_params, obj);
		if (rv)
			goto out_jo_params;


		rv = custom_json_object_array_add_string(jo_params, method);
		if (rv)
			goto out_jo_params;

		/* add the argument object at the end of the params array */
		/* jo_arg points to arg or to a new empty object */
		if (arg) {
			jo_arg = arg;
		} else {
			jo_arg = json_object_new_object();
			if (!jo_arg)
				goto out_jo_params;
		}
		rv = json_object_array_add(jo_params, jo_arg);
		if (rv) {
			if (jo_arg != arg)
				json_object_put(jo_arg);
			goto out_jo_params;
		}
	} else {
		/* prepare the params array for a ubus "list" or "subscribe" */

		rv = custom_json_object_array_add_string(jo_params, pattern);
		if (rv)
			goto out_jo_params;
	}

	/* add the params array into main json object, jo */
	json_object_object_add(jo, "params", jo_params);

	/* prepare the string for return */
	jstring = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PLAIN);
	if (!jstring)
		goto out_jo;

	string = strdup(jstring);
	/* TODO: maybe add a size limit for strdup */

out_jo_params:
	json_object_put(jo_params);
out_jo:
	json_object_put(jo);
out:
	return string;

}

char *jsonrpc__req_ubuslist(int id, const char *sid, const char *pattern)
{
	return jsonrpc__req_to_string(id, sid, "list",
			NULL, NULL, NULL, pattern);
}

char *jsonrpc__req_ubuslisten(int id, const char *sid, const char *pattern)
{
	return jsonrpc__req_to_string(id, sid, "subscribe",
			NULL, NULL, NULL, pattern);
}

char *jsonrpc__req_ubuscall(int id, const char *sid,
		const char *obj, const char *method, json_object *arg)
{

	return jsonrpc__req_to_string(id, sid, "call", obj, method, arg, NULL);
}
