#include "util_dbus.h"

#include <dbus/dbus.h>
#include <libubox/blobmsg.h>

bool check_reply_and_make_error(DBusMessage *reply, const char *expected_signature, struct blob_buf *errordata)
{
	int type = dbus_message_get_type(reply);
	if (type == DBUS_MESSAGE_TYPE_ERROR) {
		if (errordata) {
			void *data_tkt = blobmsg_open_table(errordata, "data");
			blobmsg_add_string(errordata, "DBus", dbus_message_get_error_name(reply));
			char *datastr;
			if (dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &datastr))
				blobmsg_add_string(errordata, "text", datastr);
			blobmsg_close_table(errordata, data_tkt);
		}
		return false;
	}
	if (type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		return false;
	}
	if (expected_signature && strcmp(dbus_message_get_signature(reply), expected_signature)) {
		if (errordata) {
			void *data_tkt = blobmsg_open_table(errordata, "data");
			blobmsg_add_string(errordata, "DBus", DBUS_ERROR_INVALID_SIGNATURE);
			blobmsg_close_table(errordata, data_tkt);
		}
		return false;
	}
	return true;
}

