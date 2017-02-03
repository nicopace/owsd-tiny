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
#include <libubus.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

struct wsu_local_stub {
	struct wsu_remote_bus *remote;

	struct avl_node avl;

	struct blobmsg_policy *method_args;

	struct ubus_object obj;
	struct ubus_object_type obj_type;
	struct ubus_method methods[0];
};

void wsu_local_stub_destroy(struct wsu_local_stub *stub);

bool wsu_local_stub_is_same_signature(struct wsu_local_stub *stub, json_object *signature);

struct wsu_local_stub* wsu_local_stub_create(struct wsu_remote_bus *remote, const char *object, json_object *signature);

struct wsu_local_proxied_event {
	struct blob_buf b;
	char name[0];
};


struct wsu_local_proxied_event *wsu_local_proxied_event_create(struct wsu_remote_bus *remote, const char *eventname, json_object *event_data);

void wsu_local_proxied_event_destroy(struct wsu_local_proxied_event *event);
