/*
 * Copyright (C) 2016 Inteno Broadband Technology AB
 *
 * This software is the confidential and proprietary information of the
 * Inteno Broadband Technology AB. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the
 * license agreement you entered into with the Inteno Broadband Technology AB
 *
 * All rights reserved.
 *
 * Author: Denis Osvald <denis.osvald@sartura.hr>
 *
 */
#include "common.h"

#include "ws_http.h"
#include "wsubus.h"
#include "wsubus_rpc.h"

#include <libubox/uloop.h>
#include <libubus.h>

#include <libwebsockets.h>

#include <getopt.h>
#include <locale.h>
#include <sys/resource.h>

#ifndef WSD_DEF__PORT_NO
#define WSD_DEF_PORT_NO 8843
#endif

#define WSD_2str_(_) #_
#define WSD_2str(_) WSD_2str_(_)

#ifndef WSD_DEF_CERT_PATH
#define WSD_DEF_CERT_PATH "/usr/share/owsd/cert.pem"
#endif

#ifndef WSD_DEF_PK_PATH
#define WSD_DEF_PK_PATH "/usr/share/owsd/key.pem"
#endif

#ifndef WSD_DEF_UBUS_PATH
#define WSD_DEF_UBUS_PATH "/var/run/ubus.sock"
#endif

#ifndef WSD_DEF_WWW_PATH
#define WSD_DEF_WWW_PATH "/www"
#endif

struct prog_context global;

int main(int argc, char *argv[])
{
	int rc = 0;

	const char *ubus_sock_path = WSD_DEF_UBUS_PATH;
	const char *ssl_cert_filepath = NULL;
	const char *ssl_private_key_filepath = NULL;
	const char *www_dirpath = NULL;
	int port = WSD_DEF_PORT_NO;
	struct origin origin_list = { .list = LIST_HEAD_INIT(origin_list.list)};
	char *error;
	bool ssl_wanted = false;

	int c;
	while ((c = getopt(argc, argv, "s:p:o:c:k:w:h")) != -1) {
		switch (c) {
		case 's':
			ubus_sock_path = optarg;
			break;
		case 'p':
			port = strtol(optarg, &error, 10);
			if (*error)
				goto no_ubus;
			break;
		case 'o':;
			struct origin *origin_el = calloc(1, sizeof(struct origin));
			if (!origin_el)
				break;
			origin_el->url = optarg;
			list_add_tail(&origin_el->list, &origin_list.list);
			break;
		case 'c':
			ssl_wanted = true;
			ssl_cert_filepath = optarg;
			break;
		case 'k':
			ssl_wanted = true;
			ssl_private_key_filepath = optarg;
			break;
		case 'w':
			www_dirpath = optarg;
			break;
		case 'h':
		default:
			fprintf(stderr,
					"Usage: %s [ <options> ]\n"
					"  -s <socket>      path to ubus socket [" WSD_DEF_UBUS_PATH "]\n"
					"  -p <port>        port number [" WSD_2str(WSD_DEF_PORT_NO) "]\n"
					"  -o <origin>      origin url address to whitelist\n"
					"  -c <cert_path>   SSL cert path [" WSD_DEF_CERT_PATH "]\n"
					"  -k <key_path>    SSL key path [" WSD_DEF_PK_PATH "]\n"
					"  -w <www_path>    HTTP resources path [" WSD_DEF_WWW_PATH "]\n"
					"\n", argv[0]);
			return c == 'h' ? 0 : -2;
		}
	}

	lws_set_log_level(-1, NULL);

	if (list_empty(&origin_list.list)) {
		lwsl_warn("No origins whitelisted = reject all clients\n");
	}

	if (!ssl_cert_filepath) {
		lwsl_info("Using default SSL cert path %s\n", WSD_DEF_CERT_PATH);
		if (-1 == access(WSD_DEF_CERT_PATH, R_OK)) {
			lwsl_warn("error opening default SSL cert: %s\n", strerror(errno));
		} else {
			ssl_cert_filepath = WSD_DEF_CERT_PATH;
		}
	}
	if (!ssl_private_key_filepath) {
		lwsl_info("Using default SSL key path %s\n", WSD_DEF_PK_PATH);
		if (-1 == access(WSD_DEF_PK_PATH, R_OK)) {
			lwsl_err("error opening default SSL key: %s\n", strerror(errno));
		} else {
			ssl_private_key_filepath = WSD_DEF_PK_PATH;
		}
	}
	if (!ssl_cert_filepath || !ssl_private_key_filepath) {
		lwsl_warn("SSL will not be used\n");
		ssl_cert_filepath = ssl_private_key_filepath = NULL;
		if (ssl_wanted) {
			lwsl_err("SSL cert/keys setup error\n");
			rc = 3;
			goto no_ubus;
		}
	}
	if (!www_dirpath) {
		www_dirpath = WSD_DEF_WWW_PATH;
	}

	lwsl_info("Serving dir '%s' for HTTP\n", www_dirpath);

	uloop_init();

	struct ubus_context *ubus_ctx = ubus_connect(ubus_sock_path);
	if (!ubus_ctx) {
		lwsl_err("ubus_connect error\n");
		rc = 2;
		goto no_ubus;
	}

	global.ubus_ctx = ubus_ctx;
	global.origin_list = &origin_list;
	global.www_path = www_dirpath;

	ubus_add_uloop(ubus_ctx);
	// typically 1024, so a couple of KiBs just for pointers...
	{
		struct rlimit lim = {0, 0};
		getrlimit(RLIMIT_NOFILE, &lim);
		global.num_ufds = lim.rlim_cur;
	}
	global.ufds = calloc(global.num_ufds, sizeof(struct uloop_fd*));

	setenv("TZ", "", 1);
	setlocale(LC_TIME, "C");
	tzset();

	struct lws_context_creation_info lws_info = {};

	lws_info.port = port;
	lws_info.extensions = NULL;
	lws_info.ssl_cert_filepath = ssl_cert_filepath;
	lws_info.ssl_private_key_filepath = ssl_private_key_filepath;
	lws_info.uid = -1;
	lws_info.gid = -1;
	lws_info.user = &global;

	lws_info.protocols = (struct lws_protocols[])
	{
		ws_http_proto,
		wsubus_proto,
		{ }
	};

	lwsl_debug("Creating lwsl context\n");

	struct lws_context *lws_ctx = lws_create_context(&lws_info);
	if (!lws_ctx) {
		lwsl_err("lws_create_context error\n");
		rc = 1;
		goto no_lws;
	}

	global.lws_ctx = lws_ctx;


	lwsl_info("running uloop...\n");
	uloop_run();

	wsubus_clean_all_subscriptions();

	lws_context_destroy(lws_ctx);
no_lws:

	free(global.ufds);

	ubus_free(ubus_ctx);
no_ubus:

	if (!list_empty(&origin_list.list)) {
		struct origin *origin_el, *origin_tmp;
		list_for_each_entry_safe(origin_el, origin_tmp, &origin_list.list, list) {
			list_del(&origin_el->list);
			free(origin_el);
		}
	}

	return rc;
}
