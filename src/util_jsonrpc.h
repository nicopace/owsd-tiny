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

char *jsonrpc__req_login(int id, const char *sid, const char *type);
