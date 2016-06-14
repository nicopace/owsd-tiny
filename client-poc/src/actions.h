
#pragma once

struct json_object;
struct ubus_context;

int credentials_changed(struct json_object *cred_data);

int blink_wps_led(int onoff);
