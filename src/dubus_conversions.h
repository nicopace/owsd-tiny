#include "common.h"

/** convert dbus basic type signature to corresponding ubus blobmsg type */
int duconv_type_dbus_to_ubus(int dbus_type, int dbus_elem_type);

/** convert dbus type signature to corresponding ubus blobmsg type */
int duconv_type_dbus_sigiter_to_ubus(DBusSignatureIter *dbus_sig_iter);

struct duconv_convert {
	struct blob_buf b;
	char *arg_fmt;
	int arg_num;
};

/** initialize converter structure for name-value or name-type blobs
 * @param c converter structure to initialize
 * @param arg_fmt format string, with one %d, to use if we don't have a name
 */
void duconv_convert_init(struct duconv_convert *c, const char *arg_fmt);

/** free the converter structure's resources */
void duconv_convert_free(struct duconv_convert *c);

/** convert argument signature arg_type to <arg_name>: <type> */
bool duconv_msig_dbus_to_ubus_add_arg(
		struct duconv_convert *c,
		const char *arg_type,
		const char *arg_name);

/** convert argument pointed to by msg_iter to <arg_name>: <value> */
bool duconv_msgiter_dbus_to_ubus_add_arg(
		struct duconv_convert *c,
		DBusMessageIter *msg_iter,
		const char *arg_name);

// TODO remove
/** put converted arg_name: value directly into blob, must provide arg_name*/
int duconv_msg_dbus_to_ubus(
		struct blob_buf *b,
		DBusMessageIter *msg_iter,
		const char *arg_name);

/** convert one argument from ubus blob to dbus type */
int duconv_msg_ubus_to_dbus(
		DBusMessageIter *out_iter,
		struct blob_attr *cur_arg,
		DBusSignatureIter *wanted_sig_iter);

/** convert DBus name to its expected object path, replacing '.' with '/' */
char *duconv_name_dbus_name_to_path(const char *dbus_name);

/** convert DBus object path to its expected name, replacing '/' with '.' */
char *duconv_name_dbus_path_to_name(const char *dbus_path);

/** convert ubus object name to its expected DBus object path */
char *duconv_name_ubus_to_dbus_path(const char *ubus_objname);

/** convert ubus object name to its expected DBus service and interface name */
char *duconv_name_ubus_to_dbus_name(const char *ubus_objname);

/** convert dbus service/interface name to expected ubus object name */
char *duconv_name_dbus_name_to_ubus(const char *dbus_name);

/** convert dbus object path to expected ubus object name */
char *duconv_name_dbus_path_to_ubus(const char *dbus_path);
