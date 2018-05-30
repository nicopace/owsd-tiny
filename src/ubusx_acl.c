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

#include "ubusx_acl.h"

void ubusx_acl__init()
{
	printf("ubusx_acl__init\n");
}
void ubusx_acl__destroy()
{
	printf("ubusx_acl__destroy\n");
}

void ubusx_acl__add(char *objname)
{
	printf("ubusx_acl__add objname=\"%s\"\n", objname);
}

bool ubusx_acl__allow_object(char *objname)
{
	printf("ubusx_acl__allow_object objname=\"%s\"\n", objname);
	return true;
}
bool ubusx_acl__allow_method(char *objname, char *methodname)
{
	printf("ubusx_acl__allow_method objname=\"%s\" methodname=\"%s\"\n", objname, methodname);
	return true;
}
