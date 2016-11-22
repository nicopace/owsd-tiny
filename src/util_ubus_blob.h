#pragma once
#include <libubox/blobmsg.h>
#include <assert.h>

static inline enum blobmsg_type blobmsg_type_from_str(const char *c)
{
	return
		!c        ? __BLOBMSG_TYPE_LAST :
		*c == 'a' ? BLOBMSG_TYPE_ARRAY  :
		*c == 'o' ? BLOBMSG_TYPE_TABLE  :
		*c == 's' ? BLOBMSG_TYPE_STRING :
		*c == 'n' ? BLOBMSG_TYPE_INT32  :
		*c == 'b' ? BLOBMSG_TYPE_INT8   : BLOBMSG_TYPE_UNSPEC;
}

static inline const char *blobmsg_type_to_str(enum blobmsg_type t)
{
	static const char *const lookup[] = {
		[BLOBMSG_TYPE_ARRAY] = "array",
		[BLOBMSG_TYPE_TABLE] = "object",
		[BLOBMSG_TYPE_STRING] = "string",
		[BLOBMSG_TYPE_INT32] = "number",
		[BLOBMSG_TYPE_INT16] = "number",
		[BLOBMSG_TYPE_BOOL] = "boolean",
	};
	assert(t >= 0 && t < ARRAY_SIZE(lookup));
	return lookup[t];
}

