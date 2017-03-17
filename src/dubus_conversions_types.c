#include "common.h"
#include "dubus_conversions.h"

/** private function that does all the converting logic for basic types */
static bool _duconv_dbus_to_ubus_basic(
		struct blob_buf *b,
		int dbus_type,
		int dbus_elem_type,
		DBusMessageIter *msg_iter,
		const char *ubus_arg_name)
{
	switch (dbus_type) {
	case DBUS_TYPE_UINT64:
	case DBUS_TYPE_INT64:
		if (b && msg_iter && ubus_arg_name) {
			uint64_t v64;
			dbus_message_iter_get_basic(msg_iter, &v64);
			blobmsg_add_u64(b, ubus_arg_name, v64);
		}
		return BLOBMSG_TYPE_INT64;

	case DBUS_TYPE_UINT32:
	case DBUS_TYPE_INT32:
		if (b && msg_iter && ubus_arg_name) {
			uint32_t v32;
			dbus_message_iter_get_basic(msg_iter, &v32);
			blobmsg_add_u32(b, ubus_arg_name, v32);
		}
		return BLOBMSG_TYPE_INT32;

	case DBUS_TYPE_UINT16:
	case DBUS_TYPE_INT16:
		if (b && msg_iter && ubus_arg_name) {
			uint16_t v16;
			dbus_message_iter_get_basic(msg_iter, &v16);
			blobmsg_add_u16(b, ubus_arg_name, v16);
		}
		return BLOBMSG_TYPE_INT16;

	case DBUS_TYPE_BOOLEAN:
		if (b && msg_iter && ubus_arg_name) {
			int32_t v32;
			dbus_message_iter_get_basic(msg_iter, &v32);
			blobmsg_add_u8(b, ubus_arg_name, !!v32);
		}
		return BLOBMSG_TYPE_BOOL;

	case DBUS_TYPE_OBJECT_PATH:
	case DBUS_TYPE_SIGNATURE:
	case DBUS_TYPE_STRING:
		if (b && msg_iter && ubus_arg_name) {
			char *vstr;
			dbus_message_iter_get_basic(msg_iter, &vstr);
			blobmsg_add_string(b, ubus_arg_name, vstr);
		}
		return BLOBMSG_TYPE_STRING;

	}
	return BLOBMSG_TYPE_UNSPEC;
}

/** private function that does all the converting logic or forwards to basic type function */
static bool _duconv_dbus_to_ubus(
		struct blob_buf *b,
		int dbus_type,
		int dbus_elem_type,
		DBusMessageIter *msg_iter,
		const char *ubus_arg_name)
{
	if (dbus_type_is_basic(dbus_type))
		return _duconv_dbus_to_ubus_basic(b, dbus_type, dbus_elem_type, msg_iter, ubus_arg_name);

	switch (dbus_type) {
	case DBUS_TYPE_ARRAY:
		if (!dbus_type_is_basic(dbus_elem_type))
			return BLOBMSG_TYPE_UNSPEC;

		if (b && msg_iter && ubus_arg_name) {
			DBusMessageIter rec_iter;
			void *arr = blobmsg_open_array(b, ubus_arg_name);
			for (dbus_message_iter_recurse(msg_iter, &rec_iter);
					dbus_message_iter_get_arg_type(&rec_iter) != DBUS_TYPE_INVALID;
					dbus_message_iter_next(&rec_iter)) {
				_duconv_dbus_to_ubus_basic(b, dbus_elem_type, DBUS_TYPE_INVALID, &rec_iter, "");
			}
			blobmsg_close_array(b, arr);
		}

		return BLOBMSG_TYPE_ARRAY;
	}

	return BLOBMSG_TYPE_UNSPEC;
}


int duconv_type_dbus_to_ubus(int dbus_type, int dbus_elem_type)
{
	return _duconv_dbus_to_ubus(NULL, dbus_type, dbus_elem_type, NULL, NULL);
}

int duconv_type_dbus_sigiter_to_ubus(DBusSignatureIter *dbus_sig_iter)
{
	int dbus_type = dbus_signature_iter_get_current_type(dbus_sig_iter);
	return duconv_type_dbus_to_ubus(dbus_type, dbus_type == DBUS_TYPE_ARRAY ? dbus_signature_iter_get_element_type(dbus_sig_iter) : DBUS_TYPE_INVALID);
}

int duconv_msg_dbus_to_ubus(
		struct blob_buf *b,
		DBusMessageIter *msg_iter,
		const char *arg_name)
{
	int dbus_type = dbus_message_iter_get_arg_type(msg_iter);
	int dbus_elem_type = (dbus_type == DBUS_TYPE_ARRAY ? dbus_message_iter_get_element_type(msg_iter) : DBUS_TYPE_INVALID);

	return _duconv_dbus_to_ubus(b, dbus_type, dbus_elem_type, msg_iter, arg_name);
}


void duconv_convert_init(struct duconv_convert *c, const char *arg_fmt)
{
	memset(c, 0, sizeof *c);
	blobmsg_buf_init(&c->b);
	c->arg_fmt = strdup(arg_fmt);
}

void duconv_convert_free(struct duconv_convert *c)
{
	free(c->arg_fmt);
	blob_buf_free(&c->b);
}

static char *_duconv_convert_get_next_arg(struct duconv_convert *c)
{
	int len = snprintf(NULL, 0, c->arg_fmt, c->arg_num);
	char *ret = malloc(len + 1);
	if (!ret)
		return false;
	sprintf(ret, c->arg_fmt, c->arg_num);
	++c->arg_num;
	return ret;
}

bool duconv_msig_dbus_to_ubus_add_arg(
		struct duconv_convert *c,
		const char *arg_type,
		const char *arg_name)
{
	DBusSignatureIter sig_iter;
	if (!dbus_signature_validate_single(arg_type, NULL))
		return false;

	dbus_signature_iter_init(&sig_iter, arg_type);
	int ubus_type = duconv_type_dbus_sigiter_to_ubus(&sig_iter);

	char *my_arg_name = NULL;
	if (!arg_name) {
		arg_name = _duconv_convert_get_next_arg(c);
	}

	blobmsg_add_u32(&c->b, arg_name, ubus_type);
	free(my_arg_name);
	return true;
}

bool duconv_msgiter_dbus_to_ubus_add_arg(
		struct duconv_convert *c,
		DBusMessageIter *msg_iter,
		const char *arg_name)
{
	char *my_arg_name = NULL;
	if (!arg_name) {
		arg_name = _duconv_convert_get_next_arg(c);
	}

	int ubus_type = duconv_msg_dbus_to_ubus(&c->b, msg_iter, arg_name);
	free(my_arg_name);
	return ubus_type != BLOBMSG_TYPE_UNSPEC;
}

int _duconv_msg_ubus_to_dbus_basic(
		DBusMessageIter *out_iter,
		struct blob_attr *cur_arg,
		DBusSignatureIter *wanted_sig_iter)
{
	int dbus_type = DBUS_TYPE_INVALID;
	if (wanted_sig_iter)
		dbus_type = dbus_signature_iter_get_current_type(wanted_sig_iter);

	switch (blobmsg_type(cur_arg)) {
	case BLOBMSG_TYPE_INT32:
		if (!wanted_sig_iter)
			dbus_type = DBUS_TYPE_INT32;
		if (dbus_type != DBUS_TYPE_INT32 && dbus_type != DBUS_TYPE_UINT32)
			return DBUS_TYPE_INVALID;

		if (out_iter) {
			const uint32_t res = blobmsg_get_u32(cur_arg);
			dbus_message_iter_append_basic(out_iter, dbus_type, &res);
		}

		return dbus_type;

	case BLOBMSG_TYPE_INT16:
		if (!wanted_sig_iter)
			dbus_type = DBUS_TYPE_INT16;
		if (dbus_type != DBUS_TYPE_INT16 && dbus_type != DBUS_TYPE_UINT16)
			return DBUS_TYPE_INVALID;

		if (out_iter) {
			const uint16_t res = blobmsg_get_u16(cur_arg);
			dbus_message_iter_append_basic(out_iter, dbus_type, &res);
		}

		return dbus_type;

	case BLOBMSG_TYPE_BOOL:
		if (!wanted_sig_iter)
			dbus_type = DBUS_TYPE_BOOLEAN;
		if (dbus_type != DBUS_TYPE_BOOLEAN)
			return DBUS_TYPE_INVALID;

		if (out_iter) {
			const uint8_t res = blobmsg_get_u8(cur_arg);
			const int32_t res_bool32 = (int32_t)!!res;
			dbus_message_iter_append_basic(out_iter, dbus_type, &res_bool32);
		}

		return dbus_type;

	case BLOBMSG_TYPE_STRING:
		if (!wanted_sig_iter)
			dbus_type = DBUS_TYPE_STRING;
		if (dbus_type != DBUS_TYPE_STRING && dbus_type != DBUS_TYPE_SIGNATURE && dbus_type != DBUS_TYPE_OBJECT_PATH)
			return DBUS_TYPE_INVALID;

		if (out_iter) {
			const char * const str = blobmsg_get_string(cur_arg);
			dbus_message_iter_append_basic(out_iter, dbus_type, &str);
		}

		return dbus_type;
	}

	return DBUS_TYPE_INVALID;
}

int duconv_msg_ubus_to_dbus(
		DBusMessageIter *out_iter,
		struct blob_attr *cur_arg,
		DBusSignatureIter *wanted_sig_iter)
{
	int dbus_type = DBUS_TYPE_INVALID;
	if (wanted_sig_iter)
		dbus_type = dbus_signature_iter_get_current_type(wanted_sig_iter);
	switch (blobmsg_type(cur_arg)) {
	case BLOBMSG_TYPE_ARRAY: {
		if (!wanted_sig_iter)
			dbus_type = DBUS_TYPE_ARRAY;
		if (dbus_type == DBUS_TYPE_ARRAY) {
			struct blob_attr *it; unsigned int rem;
			struct blob_attr *first = NULL;
			blob_for_each_attr(it, blobmsg_data(cur_arg), rem) {
				first = it; break;
			}
			if (!first)
				break;

			// check that elements have same signature
			blob_for_each_attr(it, blobmsg_data(cur_arg), rem)
				if (blobmsg_type(first) != blobmsg_type(it))
					return DBUS_TYPE_INVALID;

			int dbus_elem_type;
			DBusSignatureIter wanted_elem_sig_iter;
			if (wanted_sig_iter)
				dbus_signature_iter_recurse(wanted_sig_iter, &wanted_elem_sig_iter);

			dbus_elem_type = _duconv_msg_ubus_to_dbus_basic(NULL, first, wanted_sig_iter ? &wanted_elem_sig_iter : NULL);

			if (dbus_elem_type == DBUS_TYPE_INVALID)
				return DBUS_TYPE_INVALID;

			if (out_iter)
				blob_for_each_attr(it, blobmsg_data(cur_arg), rem) {
					_duconv_msg_ubus_to_dbus_basic(out_iter, it, wanted_sig_iter ? &wanted_elem_sig_iter : NULL);
					if (wanted_sig_iter)
						dbus_signature_iter_next(&wanted_elem_sig_iter);
				}

			return dbus_type;
		}
		return DBUS_TYPE_INVALID;
	}
	case BLOBMSG_TYPE_TABLE: {
		return DBUS_TYPE_INVALID;
	}
	}
	return _duconv_msg_ubus_to_dbus_basic(out_iter,  cur_arg, wanted_sig_iter);
}
