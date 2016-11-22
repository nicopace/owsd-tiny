#pragma once
#include <stdio.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>

enum jsonrpc_error_code {
	JSONRPC_ERRORCODE__OK               = 0,

	JSONRPC_ERRORCODE__PARSE_ERROR      = -32700,
	JSONRPC_ERRORCODE__INVALID_REQUEST  = -32600,
	JSONRPC_ERRORCODE__METHOD_NOT_FOUND = -32601,
	JSONRPC_ERRORCODE__INVALID_PARAMS   = -32602,
	JSONRPC_ERRORCODE__INTERNAL_ERROR   = -32603,

	JSONRPC_ERRORCODE__OTHER            = -32050,
};

char* jsonrpc__resp_error(struct blob_attr *id, int error_code, struct blob_attr *error_data);

char* jsonrpc__resp_ubus(struct blob_attr *id, int ubus_rc, struct blob_attr *ret_data);

char *jsonrpc__req_ubuslist(int id, const char *sid, const char *pattern);

char *jsonrpc__req_ubuslisten(int id, const char *sid, const char *pattern);

char *jsonrpc__req_ubuscall(int id, const char *sid, const char *obj, const char *method, json_object *arg);
