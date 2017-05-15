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

/**
 * \brief represents a local "stub" ubus object; calls to it are routed via RPC
 * to remote owsd server, then to a real ubus object living on another
 * host/bus/box/network/device
 */
struct wsu_local_stub {
	/** \brief points to struct representing connection to remote owsd server */
	struct wsu_remote_bus *remote;

	/** \brief remote stub objects are stored in a collection */
	struct avl_node avl;

	/* remainder fields store information about name/method/args/signatures/... */
	struct blobmsg_policy *method_args;

	struct ubus_object obj;
	struct ubus_object_type obj_type;
	struct ubus_method methods[0];
};

/**
 * \brief unregisters and frees/destroys the stub object
 */
void wsu_local_stub_destroy(struct wsu_local_stub *stub);

/**
 * \brief tests whether stub object has signature corresponding to JSON (that was received from list RPC)
 */
bool wsu_local_stub_is_same_signature(struct wsu_local_stub *stub, json_object *signature);

/**
 * \brief creates and registers stub object from name and JSON signature (that was received from list RPC)
 */
struct wsu_local_stub* wsu_local_stub_create(struct wsu_remote_bus *remote, const char *object, json_object *signature);

/**
 * \brief represents an event (name string + data blob) for sending to local bus
 */
struct wsu_local_proxied_event {
	struct blob_buf b;
	char name[0];
};


/**
 * \brief creates a event structure from name + data JSON (received via RPC as event)
 */
struct wsu_local_proxied_event *wsu_local_proxied_event_create(struct wsu_remote_bus *remote, const char *eventname, json_object *event_data);

/**
 * \brief destroy/free the event structure
 */
void wsu_local_proxied_event_destroy(struct wsu_local_proxied_event *event);
