#include "common.h"

#include "ws_http.h"
#include "wsubus.h"

#include <libubox/uloop.h>
#include <libubus.h>

#include <libwebsockets.h>

#include <getopt.h>

#define WSD_DEF_PORT_NO 8843

#define WSD_DEF_CERT_PATH NULL
#define WSD_DEF_PK_PATH NULL

#define WSD_DEF_UBUS_PATH "/var/run/ubus.sock"

struct prog_context global;

int main(int argc, char *argv[])
{
	int rc = 0;

	const char *ubus_sock_path = WSD_DEF_UBUS_PATH;

	int c;
	while ((c = getopt(argc, argv, "hs:")) != -1) {
		switch (c) {
		case 's':
			ubus_sock_path = optarg;
			break;

		case 'h':
		default:
			fprintf(stderr,
					"Usage: %s [ <options> ]\n"
					"  -s <socket>         path to ubus socket\n"
					"\n", argv[0]);
			return c == 'h' ? 0 : -2;
		}
	}


	uloop_init();


	struct ubus_context *ubus_ctx = ubus_connect(ubus_sock_path ? ubus_sock_path : WSD_DEF_UBUS_PATH);
	if (!ubus_ctx) {
		lwsl_err("ubus_connect error\n");
		rc = 2;
		goto no_ubus;
	}

	global.ubus_ctx = ubus_ctx;


	ubus_add_uloop(ubus_ctx);
	// dtablesize is typically 1024, so a couple of KiBs just for pointers...
	//
	global.num_ufds = getdtablesize();
	global.ufds = calloc(global.num_ufds, sizeof(struct uloop_fd*));


	struct lws_context_creation_info lws_info = {};

	lws_info.port = WSD_DEF_PORT_NO;
	lws_info.extensions = libwebsocket_get_internal_extensions();
	lws_info.ssl_cert_filepath = WSD_DEF_CERT_PATH;
	lws_info.ssl_private_key_filepath = WSD_DEF_PK_PATH;
	lws_info.uid = -1;
	lws_info.gid = -1;
	lws_info.user = &global;

	lws_set_log_level(-1, NULL);

	lws_info.protocols = (struct libwebsocket_protocols[])
	{
		ws_http_proto,
		wsubus_proto,
		{ }
	};

	lwsl_debug("Creating lwsl context\n");

	struct libwebsocket_context *lws_ctx = libwebsocket_create_context(&lws_info);
	if (!lws_ctx) {
		lwsl_err("libwebsocket_create_context error\n");	
		rc = 1;
		goto no_lws;
	}

	global.lws_ctx = lws_ctx;


	lwsl_info("running uloop...\n");
	uloop_run();

	libwebsocket_context_destroy(lws_ctx);
no_lws:

	free(global.ufds);

	ubus_free(ubus_ctx);
no_ubus:


	return rc;
}
