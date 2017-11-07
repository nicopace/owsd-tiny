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
#include "common.h"

#include "ws_http.h"
#include "wsubus.h"
#include "wsubus_client.h"
#include "rpc.h"

#if WSD_HAVE_DBUS
#include "dbus-io.h"
#include <dbus/dbus.h>
#endif
#if WSD_HAVE_UBUS
#include <libubus.h>
#endif

#include <libubox/uloop.h>
#include <libwebsockets.h>

#include <getopt.h>
#include <locale.h>
#include <sys/resource.h>

#ifndef WSD_DEF_UBUS_PATH
#define WSD_DEF_UBUS_PATH "/var/run/ubus.sock"
#endif

#ifndef WSD_DEF_WWW_PATH
#define WSD_DEF_WWW_PATH "/www"
#endif

#ifndef WSD_DEF_WWW_MAXAGE
#define WSD_DEF_WWW_MAXAGE 0
#endif

struct prog_context global;

static void usage(char *name)
{
	fprintf(stderr,
			"Usage: %s <global options> [[-p <port>] <per-port options> ] ...\n\n"
			" global options:\n"
			"  -s <socket>      path to ubus socket [" WSD_DEF_UBUS_PATH "]\n"
			"  -w <www_path>    HTTP resources path [" WSD_DEF_WWW_PATH "]\n"
			"  -t <www_maxage>  enable HTTP caching with specified max_age in seconds\n"
			"  -r <from>:<to>   HTTP path redirect pair\n"
			"  -m <from>:<to>   CGI mount point\n"
#if WSD_HAVE_UBUSPROXY
			"  -U               Enable WS ubus proxying\n"
			"  -P <url> ...     URL of remote WS ubus to proxy as client\n"
			"                   (also activates -U )"
#ifdef LWS_OPENSSL_SUPPORT
			"  -C <cert_path>   SSL client cert path\n"
			"  -K <cert_path>   SSL client key path\n"
			"  -A <ca_file>     SSL CA file path trusted by client\n"
#endif // LWS_OPENSSL_SUPPORT
#endif
			"\n"
			"  -p <port> ...    port number (repeat for multiple):\n"
			" per-port options (apply to last port (-p))\n"
			"  -L <label>       _owsd_listen label\n"
			"  -i <interface>   interface to bind to \n"
			"  -o <origin> ...  origin url address to whitelist\n"
			"  -u <user> ...    restrict login to this rpcd user\n"
#ifdef LWS_WITH_IPV6
			"  -6               enable IPv6, repeat to disable IPv4 [off]\n"
#endif // LWS_WITH_IPV6
#ifdef LWS_OPENSSL_SUPPORT
			"  -c <cert_path>   SSL cert path if SSL wanted\n"
			"  -k <key_path>    SSL key path if SSL wanted\n"
			"  -a <ca_file>     path to SSL CA file that makes clients trusted\n"
#endif // LWS_OPENSSL_SUPPORT
			"Options with ... are repeatable (e.g. -u one -u two ...)\n"
			"\n", name);
}

void utimer_service(struct uloop_timeout *utimer)
{
	struct prog_context *prog = container_of(utimer, struct prog_context, utimer);
	// inform LWS that a second has passed
	lws_service_fd(prog->lws_ctx, NULL);
	uloop_timeout_set(utimer, 1000);
}

static void sigchld_handler(int signo)
{
	return;
}

static bool install_handler(int signum, void (*handler)(int))
{
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	sa.sa_flags = 0;
	if (sigaction(signum, &sa, NULL) == -1) {
		lwsl_err("signal handler install: %s\n", strerror(errno));
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	int rc = 0;

#if WSD_HAVE_UBUS
	const char *ubus_sock_path = WSD_DEF_UBUS_PATH;
#endif
	const char *www_dirpath = WSD_DEF_WWW_PATH;
	int www_maxage = WSD_DEF_WWW_MAXAGE;
	char *redir_from = NULL;
	char *redir_to = NULL;
	char *cgi_from = NULL;
	char *cgi_to = NULL;
	bool any_ssl = false;

	// list of per-vhost creation_info structs, with custom per-vhost storage
	struct vhinfo_list {
		struct lws_context_creation_info vh_info;
		struct vhinfo_list *next;
		struct vh_context vh_ctx;
	} *currvh = NULL;

	int c;
	while ((c = getopt(argc, argv,
					/* global */
#if WSD_HAVE_UBUS
					"s:"
#endif /* WSD_HAVE_UBUSPROXY */
					"w:t:r:m:h"

#if WSD_HAVE_UBUSPROXY
					"U"
					/* per-client */
					"P:"
#ifdef LWS_OPENSSL_SUPPORT
					"C:K:A:"
#endif /* LWS_OPENSSL_SUPPORT */
#endif /* WSD_HAVE_UBUSPROXY */
					/* per-vhost */
					"p:i:o:L:u:"
#ifdef LWS_WITH_IPV6
					"6"
#endif // LWS_WITH_IPV6
#ifdef LWS_OPENSSL_SUPPORT
					"c:k:a:"
#endif // LWS_OPENSSL_SUPPORT
					)) != -1) {
		switch (c) {
#if WSD_HAVE_UBUS
		case 's':
			ubus_sock_path = optarg;
			break;
#endif /* WSD_HAVE_UBUS */
		case 'w':
			www_dirpath = optarg;
			break;
		case 't': {
			char *error;
			int secs = strtol(optarg, &error, 10);
			if (*error) {
				lwsl_err("Invalid maxage '%s' specified\n", optarg);
				goto error;
			}
			www_maxage = secs;
			break;
		}
		case 'r':
			redir_to = strchr(optarg, ':');
			if (!redir_to) {
				lwsl_err("invalid redirect pair specified");
				goto error;
			}
			*redir_to++ = '\0';
			redir_from = optarg;
			break;
		case 'm':
			cgi_to = strchr(optarg, ':');
			if (!cgi_to) {
				lwsl_err("invalid cgi origin specified");
				goto error;
			}
			*cgi_to++ = '\0';
			cgi_from = optarg;
			break;

			// client
#if WSD_HAVE_UBUSPROXY
		case 'U':
			any_ssl = true;
			wsubus_client_enable_proxy();
			break;
		case 'P': {

			const char *proto, *addr, *path;
			int port;
			if (lws_parse_uri(optarg, &proto, &addr, &port, &path)) {
				lwsl_err("invalid connect URL for client\n");
				goto error;
			}
			if (strncmp(proto, "wss", 4) != 0) {
				lwsl_err("only wss protocol for WS proxy client\n");
				goto error;
			}
			any_ssl = true;
			wsubus_client_create(addr, port, path, CLIENT_FROM_PROGARG);
			break;
		}
#ifdef LWS_OPENSSL_SUPPORT
			// following options tweak options for connecting as proxy
		case 'C':
			wsubus_client_set_cert_filepath(optarg);
			break;
		case 'K':
			wsubus_client_set_private_key_filepath(optarg);
			break;
		case 'A':
			wsubus_client_set_ca_filepath(optarg);
			break;
#endif
#endif // WSD_HAVE_UBUSPROXY

			// vhost
		case 'p': {
			struct vhinfo_list *newvh = malloc(sizeof *newvh);
			if (!newvh) {
				lwsl_err("OOM vhinfo init\n");
				goto error;
			}

			*newvh = (struct vhinfo_list){};
			INIT_LIST_HEAD(&newvh->vh_ctx.origins);
			INIT_LIST_HEAD(&newvh->vh_ctx.users);
			newvh->vh_ctx.name = "";
			newvh->vh_info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;

			char *error;
			int port = strtol(optarg, &error, 10);
			if (*error) {
				lwsl_err("Invalid port '%s' specified\n", optarg);
				goto error;
			}
			newvh->vh_info.port = port;
			newvh->vh_ctx.name = optarg;

			// add this listening vhost into our list
			newvh->next = currvh;
			currvh = newvh;
			break;
		}
			// following options affect last added vhost
			// currvh (and assume there is one)
		case 'i':
			currvh->vh_info.iface = optarg;
			break;
		case 'o': {
			struct str_list *str = malloc(sizeof *str);
			if (!str)
				break;
			str->str = optarg;
			list_add_tail(&str->list, &currvh->vh_ctx.origins);
			break;
		}
		case 'u': {
			struct str_list *str = malloc(sizeof *str);
			if (!str)
				break;
			str->str = optarg;
			list_add_tail(&str->list, &currvh->vh_ctx.users);
			break;
		}
		case 'L':
			currvh->vh_ctx.name = optarg;
			break;
#ifdef LWS_WITH_IPV6
		case '6':
			if (currvh->vh_info.options & LWS_SERVER_OPTION_DISABLE_IPV6) {
				currvh->vh_info.options &= ~LWS_SERVER_OPTION_DISABLE_IPV6;
			} else {
				currvh->vh_info.options |= LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY | LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE;
			}
			break;
#endif // LWS_WITH_IPV6
#ifdef LWS_OPENSSL_SUPPORT
		case 'c':
			currvh->vh_info.ssl_cert_filepath = optarg;
			goto ssl;
		case 'k':
			currvh->vh_info.ssl_private_key_filepath = optarg;
			goto ssl;
		case 'a':
			currvh->vh_info.ssl_ca_filepath = optarg;
			goto ssl;

ssl:
			any_ssl = true;
			currvh->vh_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			break;
#endif // LWS_OPENSSL_SUPPORT

		case 'h':
		default:
			usage(argv[0]);
			return c == 'h' ? 0 : -2;
		}
	}

	argc -= optind;
	argv += optind;

	lws_set_log_level(-1, NULL);

	if (!install_handler(SIGCHLD, sigchld_handler))
		goto error;

	uloop_init();

	// connect to bus(es)

#if WSD_HAVE_UBUS
	struct ubus_context *ubus_ctx = ubus_connect(ubus_sock_path);
	if (!ubus_ctx) {
		lwsl_err("ubus_connect error\n");
		rc = 2;
		goto error;
	}
	global.ubus_ctx = ubus_ctx;
	ubus_add_uloop(ubus_ctx);
#endif

#if WSD_HAVE_DBUS
	struct DBusConnection *dbus_ctx;
	{
		struct DBusError error;
		dbus_error_init(&error);
		dbus_ctx = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
		if (!ubus_ctx || dbus_error_is_set(&error)) {
			lwsl_err("dbus_connect error\n");
			lwsl_err("DBUS erro %s : %s\n", error.name, error.message);
			rc = 2;
			goto error;
		}
		global.dbus_ctx = dbus_ctx;
		wsd_dbus_add_to_uloop(dbus_ctx);
	}
#endif

	global.www_path = www_dirpath;
	global.redir_from = redir_from;
	global.redir_to = redir_to;

	lwsl_info("Will serve dir '%s' for HTTP\n", www_dirpath);

	// allocate file descriptor watchers
	// typically 1024, so a couple of KiBs just for pointers...
	{
		struct rlimit lim = {0, 0};
		getrlimit(RLIMIT_NOFILE, &lim);
		global.num_ufds = lim.rlim_cur;
	}
	global.ufds = calloc(global.num_ufds, sizeof(struct uloop_fd*));

	// switch to UTC for HTTP timestamp format
	setenv("TZ", "", 1);
	setlocale(LC_TIME, "C");
	tzset();

	// lws context constructor under which are all vhosts
	struct lws_context_creation_info lws_info = {};

	lws_info.uid = -1;
	lws_info.gid = -1;
	lws_info.user = &global;
	lws_info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS | (any_ssl ? LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT : 0);
	lws_info.server_string = "owsd";
	lws_info.ws_ping_pong_interval = 300;

	lwsl_debug("Creating lwsl context\n");

	struct lws_context *lws_ctx = lws_create_context(&lws_info);
	if (!lws_ctx) {
		lwsl_err("lws_create_context error\n");
		rc = 1;
		goto error_ubus_ufds;
	}

	global.lws_ctx = lws_ctx;

	// these protocols and the wwwmount are connected to all vhosts
	struct lws_protocols ws_protocols[] = {
		ws_http_proto,
		wsubus_proto,
		{ }
	};

	// we tell lws to serve something that will always fail at
	// libwebsockets-level, so we can run our own HTTP serving with tweaks
	// TODO consider getting rid of our tweaks in favor of using lws ...
	static struct lws_http_mount wwwmount = {
		NULL,
		"/",
		"/dev/null/",   // anything not-a-dir is ok, so our HTTP code runs and not lws
		"index.html"
	};
	wwwmount.cache_reusable = !!www_maxage;
	wwwmount.cache_revalidate = !!www_maxage;
	wwwmount.cache_max_age = www_maxage;
	wwwmount.mountpoint_len = strlen(wwwmount.mountpoint);
	wwwmount.origin_protocol = LWSMPRO_FILE;

  // cgi environment variables
  const static struct lws_protocol_vhost_options cgienv4 = {
    .name = "PATH",
    .value = "/bin:/usr/bin:/usr/local/bin:/usr/sbin:/sbin:/var/www/cgi-bin",
  };

  const static struct lws_protocol_vhost_options cgienv3 = {
    .next = &cgienv4,
    .name = "SCRIPT_NAME",
    .value = "/cgi-bin/luci",
  };

  const static struct lws_protocol_vhost_options cgienv2 = {
    .next = &cgienv3,
    .name = "SCRIPT_FILENAME",
    .value = "/www/cgi-bin/luci",
  };

  const static struct lws_protocol_vhost_options cgienv1 = {
    .next = &cgienv2,
    .name = "DOCUMENT_ROOT",
    .value = "/www",
  };

	// create mount for the CGI
	static struct lws_http_mount cgimount = {
		.mount_next = &wwwmount,
		.mountpoint = "/cgi-bin/luci",
		.origin = "/www/cgi-bin/luci",
		.cgienv = &cgienv1,
		.cgi_timeout = 5000,
		.origin_protocol = LWSMPRO_CGI,
	};
	cgimount.mountpoint_len = strlen(cgimount.mountpoint);

	if (cgi_from && cgi_to) {
		cgimount.mountpoint = cgi_from;
		cgimount.mountpoint_len = strlen(cgimount.mountpoint);
		cgimount.origin = cgi_to;
	}

	// create all listening vhosts
	for (struct vhinfo_list *c = currvh; c; c = c->next) {
		c->vh_info.protocols = ws_protocols;

		c->vh_info.mounts = &cgimount;

		// tell SSL clients to include their certificate but don't fail if they don't
		if (c->vh_info.ssl_ca_filepath) {
			c->vh_info.options |= LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED | LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
		}

		lwsl_debug("create vhost for port %d with %s , c %s k %s\n", c->vh_info.port, (c->vh_info.options & LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT) ? "ssl" : "no ssl",
				c->vh_info.ssl_cert_filepath, c->vh_info.ssl_private_key_filepath);

		struct lws_vhost *vh = lws_create_vhost(lws_ctx, &c->vh_info);

		if (!vh) {
			lwsl_err("lws_create_vhost error\n");
			rc = 1;
			goto error_ubus_ufds_ctx;
		}

		// per-vhost storage is lws-allocated
		struct vh_context **pvh_context = lws_protocol_vh_priv_zalloc(vh, &c->vh_info.protocols[1] /* ubus */, sizeof pvh_context);

		// we allocate a pointer and point to per-vhost storage
		*pvh_context = &c->vh_ctx;
	}

#if WSD_HAVE_UBUSPROXY
	wsubus_client_start_proxying(lws_ctx, ubus_ctx);
#endif

	global.utimer.cb = utimer_service;
	uloop_timeout_add(&global.utimer);
	uloop_timeout_set(&global.utimer, 1000);

	lwsl_info("running uloop...\n");
	uloop_run();

#if WSD_HAVE_UBUSPROXY
	wsubus_client_clean();
#endif

	// free the per-vhost contexts
	for (struct vhinfo_list *c = currvh, *prev = NULL; c; prev = c, c = c->next, free(prev)) {
		struct vh_context *vc = &c->vh_ctx;
		if (vc && !list_empty(&vc->origins)) {
			struct str_list *origin_el, *origin_tmp;
			list_for_each_entry_safe(origin_el, origin_tmp, &vc->origins, list) {
				list_del(&origin_el->list);
				free(origin_el);
			}
		}
		if (vc && !list_empty(&vc->users)) {
			struct str_list *user_el, *user_tmp;
			list_for_each_entry_safe(user_el, user_tmp, &vc->users, list) {
				list_del(&user_el->list);
				free(user_el);
			}
		}
	}

error_ubus_ufds_ctx:
	lws_context_destroy(lws_ctx);

error_ubus_ufds:
	free(global.ufds);

#if WSD_HAVE_UBUS
	ubus_free(ubus_ctx);
#endif
#if WSD_HAVE_DBUS
	dbus_connection_close(dbus_ctx);
	dbus_connection_unref(dbus_ctx);
	dbus_shutdown();
#endif

error:

	return rc;
}
