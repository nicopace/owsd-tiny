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

#ifndef WSD_DEF_UBUS_PATH
#define WSD_DEF_UBUS_PATH "/var/run/ubus.sock"
#endif

#ifndef WSD_DEF_WWW_PATH
#define WSD_DEF_WWW_PATH "/www"
#endif

#ifndef WSD_MAX_VHOSTS
#define WSD_MAX_VHOSTS 4
#endif

void utimer_service(struct uloop_timeout *utimer)
{
	struct prog_context *prog = container_of(utimer, struct prog_context, utimer);

	lws_service_fd(prog->lws_ctx, NULL);
	uloop_timeout_set(utimer, 1000);
}

struct prog_context global;

static void vh_init_default(struct lws_context_creation_info *vh) {
	static const struct lws_context_creation_info default_vh = {
		.port = WSD_DEF_PORT_NO,
	};

	*vh = default_vh;
	vh->user = malloc(sizeof(struct list_head));
	INIT_LIST_HEAD(vh->user);

	vh->options |= LWS_SERVER_OPTION_DISABLE_IPV6; // FIXME lwsbug ipv6 doesn't work with iface
}

int main(int argc, char *argv[])
{
	int rc = 0;

	const char *ubus_sock_path = WSD_DEF_UBUS_PATH;
	const char *www_dirpath = WSD_DEF_WWW_PATH;
	char *redir_from = NULL;
	char *redir_to = NULL;
	bool any_ssl = false;

	struct lws_context_creation_info vh_info[WSD_MAX_VHOSTS] = { };
	struct lws_context_creation_info *curr_vh_info = vh_info;
	bool have_vh = false;
	vh_init_default(curr_vh_info);

	int c;
	while ((c = getopt(argc, argv,
					/* global */
					"s:w:r:h"
					/* per-vhost */
					"p:i:o:"
#ifdef LWS_USE_IPV6
					"6"
#endif // LWS_USE_IPV6
#ifdef LWS_OPENSSL_SUPPORT
					"c:k:"
#endif // LWS_OPENSSL_SUPPORT
					)) != -1) {
		switch (c) {
		case 's':
			ubus_sock_path = optarg;
			break;
		case 'w':
			www_dirpath = optarg;
			break;
		case 'r':
			redir_to = strchr(optarg, ':');
			if (!redir_to) {
				lwsl_err("invalid redirect pair specified");
				goto error;
			}
			*redir_to++ = '\0';
			redir_from = optarg;
			break;

		case 'p':
			if (!have_vh) {
				have_vh = true;
			} else if (curr_vh_info >= vh_info + ARRAY_SIZE(vh_info)) {
				lwsl_err("Too many ports [ max " WSD_2str(WSD_MAX_VHOSTS) " ]");
				goto error;
			} else {
				vh_init_default(++curr_vh_info);
			}

			char *error;
			int port = strtol(optarg, &error, 10);
			if (*error) {
				lwsl_err("Invalid port specified");
				goto error;
			}

			curr_vh_info->port = port;
			break;
		case 'i':
			curr_vh_info->iface = optarg;
			break;
		case 'o':;
			struct origin *origin_el = malloc(sizeof(struct origin));
			if (!origin_el)
				break;
			origin_el->url = optarg;
			list_add_tail(&origin_el->list, curr_vh_info->user);
			break;
#ifdef LWS_USE_IPV6
		case '6':
			if (curr_vh_info->options & LWS_SERVER_OPTION_DISABLE_IPV6) {
				curr_vh_info->options &= ~LWS_SERVER_OPTION_DISABLE_IPV6;
			} else {
				curr_vh_info->options |= LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY | LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE;
			}
			break;
#endif // LWS_USE_IPV6
#ifdef LWS_OPENSSL_SUPPORT
		case 'c':
			curr_vh_info->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			curr_vh_info->ssl_cert_filepath = optarg;
			any_ssl = true;
			break;
		case 'k':
			curr_vh_info->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			curr_vh_info->ssl_private_key_filepath = optarg;
			break;
#endif // LWS_OPENSSL_SUPPORT

		case 'h':
		default:
			fprintf(stderr,
					"Usage: %s <global options> [[-p <port>] <per-port options> ] ...\n\n"
					" global options:\n"
					"  -s <socket>      path to ubus socket [" WSD_DEF_UBUS_PATH "]\n"
					"  -w <www_path>    HTTP resources path [" WSD_DEF_WWW_PATH "]\n"
					"  -r <from>:<to>   HTTP path redirect pair\n"
					" per-port options:\n"
					"  -p <port>        port number [" WSD_2str(WSD_DEF_PORT_NO) "]\n"
					"  -i <interface>   interface to bind to \n"
					"  -o <origin>      origin url address to whitelist\n"
#ifdef LWS_USE_IPV6
					"  -6               enable IPv6, repeat to disable IPv4 [off]\n"
#endif // LWS_USE_IPV6
#ifdef LWS_OPENSSL_SUPPORT
					"  -c <cert_path>   SSL cert path if SSL wanted\n"
					"  -k <key_path>    SSL key path if SSL wanted\n"
#endif // LWS_OPENSSL_SUPPORT
					"\n", argv[0]);
			return c == 'h' ? 0 : -2;
		}
	}

	lws_set_log_level(-1, NULL);

	uloop_init();

	struct ubus_context *ubus_ctx = ubus_connect(ubus_sock_path);
	if (!ubus_ctx) {
		lwsl_err("ubus_connect error\n");
		rc = 2;
		goto error;
	}

	global.ubus_ctx = ubus_ctx;
	global.www_path = www_dirpath;
	global.redir_from = redir_from;
	global.redir_to = redir_to;

	lwsl_info("Will serve dir '%s' for HTTP\n", www_dirpath);

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

	lws_info.uid = -1;
	lws_info.gid = -1;
	lws_info.user = &global;
	lws_info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS | (any_ssl ? LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT : 0);
	lws_info.server_string = "owsd";

	lwsl_debug("Creating lwsl context\n");

	struct lws_context *lws_ctx = lws_create_context(&lws_info);
	if (!lws_ctx) {
		lwsl_err("lws_create_context error\n");
		rc = 1;
		goto error_ubus_ufds;
	}

	global.lws_ctx = lws_ctx;

	struct lws_protocols ws_protocols[] = {
		ws_http_proto,
		wsubus_proto,
		{ }
	};

	struct lws_http_mount wwwmount = {
		NULL,
		"/",
		"/dev/null/",   // anything not-a-dir is ok, so our HTTP code runs and not lws
		"index.html",
		NULL, NULL, 0,  // no CGI
		3600,           // cache_max_age
		1, 1, 0,        // reuse cache, revalidate cache, private cache
		LWSMPRO_FILE,
		1,              // strlen of "/"
	};

	int num = 0;

	for (struct lws_context_creation_info *c = vh_info; c <= curr_vh_info; ++c) {
		c->protocols = ws_protocols;
		c->mounts = &wwwmount;

		lwsl_debug("create vhost %d for port %d with %s , c %s k %s\n", ++num, c->port, (c->options & LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT) ? "ssl" : "no ssl",
				c->ssl_cert_filepath, c->ssl_private_key_filepath);

		struct lws_vhost *vh = lws_create_vhost(lws_ctx, c);

		if (!vh) {
			lwsl_err("lws_create_vhost error\n");
			rc = 1;
			goto error_ubus_ufds_ctx;
		}

		struct list_head *vh_origins = lws_protocol_vh_priv_zalloc(vh, &c->protocols[1] /* ubus */, sizeof *vh_origins);
		INIT_LIST_HEAD(vh_origins);
		list_splice(c->user, vh_origins);

		free(c->user);
		c->user = NULL;

		if (list_empty(vh_origins)) {
			lwsl_warn("No origins whitelisted on port %d = reject all ws clients\n", c->port);
		}

	}

	global.utimer.cb = utimer_service;
	uloop_timeout_add(&global.utimer);
	uloop_timeout_set(&global.utimer, 1000);

	lwsl_info("running uloop...\n");
	uloop_run();

	wsubus_clean_all_subscriptions();

error_ubus_ufds_ctx:
	lws_context_destroy(lws_ctx);

error_ubus_ufds:
	free(global.ufds);

	ubus_free(ubus_ctx);

error:

	return rc;
}
