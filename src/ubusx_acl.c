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
#include <stdio.h>
#include <libubus.h>
#include <libubox/avl-cmp.h>
#include "ubusx_acl.h"

struct avl_tree uxacl_objects = AVL_TREE_INIT(uxacl_objects, avl_strcmp, false, NULL);

void ubusx_acl__init()
{
	printf("ubusx_acl__init\n");
}
void ubusx_acl__destroy()
{
	printf("ubusx_acl__destroy\n");
}

void ubusx_acl__add_objects(char *objects)
{
	char *obj;
	char *saveptr1;

	if (!objects)
		return;
	if (strlen(objects) == 0)
		return;

	printf("ubusx_acl__add_list objnames=\"%s\"\n", objects);

	obj = strtok_r(objects, " ", &saveptr1);
	for (; obj; obj = strtok_r(NULL, " ", &saveptr1)) {
		printf("obj = \"%s\"\n", obj);
	}
}

void ubusx_acl__add(char *objname)
{
	int rv;
	struct avl_node *node;

	printf("ubusx_acl__add objname=\"%s\"\n", objname);

	node = calloc(1, sizeof(*node));
	if (!node) {
		perror("calloc");
		goto out;
	}

	node->key = strdup(objname);
	if (!node->key) {
		perror("strdup");
		goto out_node;
	}

	rv = avl_insert(&uxacl_objects, node);
	if (rv) {
		printf("avl_insert failed\n");
		goto out_key;
	}

out_key:
	free((void *)node->key);
out_node:
	free(node);
out:
	return;
}

bool ubusx_acl__allow_object(char *objname)
{
	printf("ubusx_acl__allow_object objname=\"%s\"\n", objname);

	if (avl_is_empty(&uxacl_objects))
		return true;

	if (avl_find(&uxacl_objects, objname))
		return true;
	return false;
}

bool ubusx_acl__allow_method(char *objname, char *methodname)
{
	printf("ubusx_acl__allow_method objname=\"%s\" methodname=\"%s\"\n", objname, methodname);
	return true;
}
