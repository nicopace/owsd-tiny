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
