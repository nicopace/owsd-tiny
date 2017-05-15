/*
 * Copyright (C) 2017 Inteno Broadband Technology AB. All rights reserved.
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

#include <stdbool.h>

typedef struct DBusMessage DBusMessage;
struct blob_buf;

/**
 * \brief check that the DBus message is a method return, optionally with expected signature
 *
 * \param reply message to check
 * \param expected_signature expected signature, or NULL to skip signature check
 * \param errordata if non-NULL, will be filled-in with a "DBus" string field with error text as value
 */
bool check_reply_and_make_error(DBusMessage *reply, const char *expected_signature, struct blob_buf *errordata);
