/*
 * Copyright (C) 2018 Inteno Broadband Technology AB. All rights reserved.
 *
 * Author: Alex Oprea <ionutalexoprea@gmail.com>
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

/*
 * ubusx_acl: access control list implementation
 * for exposing local ubus object on remote/extended ubuses(a.k.a. ubusx)
 */
#ifndef UBUSX_ACL_H
#define UBUSX_ACL_H

void ubusx_acl__init(void);
void ubusx_acl__destroy(void);

void ubusx_acl__add_object(char *object);
void ubusx_acl__add_objects(char *objects);
bool ubusx_acl__allow_object(const char *objname);
bool ubusx_acl__allow_method(const char *objname, const char *methodname);

#endif
