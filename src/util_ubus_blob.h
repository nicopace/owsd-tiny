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
#include <libubox/blobmsg.h>
#include <assert.h>

/**
 * \brief convert text representation (from JSON) to enum
 */
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

/**
 * \brief convert enum blobmsg type to textual representation for JSON
 */
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

