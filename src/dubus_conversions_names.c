#include "common.h"
#include "dubus_conversions.h"

char *duconv_name_dbus_name_to_path(const char *dbus_name)
{
	char *dbus_path = strdup(dbus_name);
	for (char *p = dbus_path; (p = strchr(p, '.')); ++p)
		*p = '/';

	return dbus_path;
}
char *duconv_name_dbus_path_to_name(const char *dbus_path)
{
	char *dbus_name = strdup(dbus_path+1);
	for (char *p = dbus_name; (p = strchr(p, '/')); ++p)
		*p = '.';

	return dbus_name;
}

char *duconv_name_ubus_to_dbus_path(const char *ubus_objname)
{
	char *dbus_path = malloc(strlen(ubus_objname) + 1 + sizeof(WSD_DBUS_OBJECTS_PATH));
	dbus_path[0] = '\0';
	strcat(dbus_path, WSD_DBUS_OBJECTS_PATH);
	if (ubus_objname[0] != '/')
		strcat(dbus_path, "/");
	strcat(dbus_path, ubus_objname);
	for (char *p = dbus_path; (p = strchr(p, '.')); ++p)
		*p = '/';
	return dbus_path;
}

char *duconv_name_ubus_to_dbus_name(const char *ubus_objname)
{
	char *tmp = duconv_name_ubus_to_dbus_path(ubus_objname);
	char *ret = duconv_name_dbus_path_to_name(tmp);
	free(tmp);
	return ret;
}

char *duconv_name_dbus_name_to_ubus(const char *dbus_name)
{
	char *tmp = duconv_name_dbus_path_to_name(WSD_DBUS_OBJECTS_PATH);
	size_t tmp_len = strlen(tmp);
	char *ret = NULL;
	if (strstr(dbus_name, tmp) == dbus_name && dbus_name[tmp_len] && dbus_name[tmp_len] == '.' && dbus_name[tmp_len+1]) {
		ret = strdup(dbus_name + tmp_len + 1);
	}
	free(tmp);
	return ret;
}

char *duconv_name_dbus_path_to_ubus(const char *dbus_path)
{
	size_t tmp_len = strlen(WSD_DBUS_OBJECTS_PATH);
	char *ret = NULL;
	if (strstr(dbus_path, WSD_DBUS_OBJECTS_PATH) == dbus_path && dbus_path[tmp_len] && dbus_path[tmp_len] == '/' && dbus_path[tmp_len+1]) {
		ret = strdup(dbus_path + tmp_len + 1);
	}
	return ret;
}
