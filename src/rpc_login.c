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

/*
 * ubus over websocket - ubus event subscription
 */
#include "rpc_login.h"

#include "common.h"
#include "wsubus.impl.h"
#include "rpc.h"

#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubus.h>

#include <assert.h>


int ubusrpc_blob_authreq_parse(struct ubusrpc_blob *ubusrpc, struct blob_attr *blob)
{
	static const struct blobmsg_policy rpc_ubus_param_policy[] = {
		[0] = { .type = BLOBMSG_TYPE_STRING }, // ubus-session id
		[1] = { .type = BLOBMSG_TYPE_STRING }, // auth req type
	};
	enum { __RPC_L_MAX = (sizeof rpc_ubus_param_policy / sizeof rpc_ubus_param_policy[0]) };
	struct blob_attr *tb[__RPC_L_MAX];

	blobmsg_parse_array(rpc_ubus_param_policy, __RPC_L_MAX, tb, blobmsg_data(blob), (unsigned)blobmsg_len(blob));

	if (!tb[1])
		return 3;

	struct blob_attr *dup_blob = blob_memdup(blob);
	if (!dup_blob) {
		return -100;
	}

	ubusrpc->login.src_blob = dup_blob;
	ubusrpc->login.sid = tb[0] ? blobmsg_get_string(tb[0]) : UBUS_DEFAULT_SID;
	ubusrpc->login.auth_type = blobmsg_get_string(tb[1]);

	return 0;
}

int ubusrpc_handle_authreq(struct lws *wsi, struct ubusrpc_blob *ubusrpc, struct blob_attr *id)
{
	struct wsu_peer *peer = wsi_to_peer(wsi);

#ifdef LWS_OPENSSL_SUPPORT
	if (!strcmp("tls-certificate", ubusrpc->login.auth_type)) {
		SSL *ssl = lws_get_ssl(wsi);
		X509 *x;
		if ((x = SSL_get_peer_certificate(ssl)) && SSL_get_verify_result(ssl) == X509_V_OK) {
			X509_NAME *xname = X509_get_subject_name(x);
			X509_NAME_get_text_by_NID(xname, NID_commonName, peer->tls.cert_subj, sizeof peer->tls.cert_subj);
			X509_free(x);
			lwsl_notice("wsi %p was TLS authenticated with cert CN= %s\n", wsi, peer->tls.cert_subj);

			struct blob_buf b = {};
			blob_buf_init(&b, 0);
			blobmsg_add_string(&b, "CN", peer->tls.cert_subj);

			char sid[UBUS_SID_MAX_STRLEN] = SID_EXTENDED_PREFIX;
			strncat(sid, ubusrpc->login.auth_type, sizeof sid - strlen(sid) - 1);

			wsu_sid_check_and_update(peer, sid);

			char *resp = jsonrpc__resp_ubus(id, 0, b.head);
			blob_buf_free(&b);
			wsu_queue_write_str(wsi, resp);
			free(resp);
		} else {
			lwsl_notice("wsi %p was not TLS authenticated\n", wsi);

			char *resp = jsonrpc__resp_error(id, 403, NULL);
			wsu_queue_write_str(wsi, resp);
			free(resp);
		}
	} else
#endif
	{
	}

	free(ubusrpc->login.src_blob);
	free(ubusrpc);

	return 0;
}
