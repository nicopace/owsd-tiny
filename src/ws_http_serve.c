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
#include "ws_http_serve.h"
#include "common.h"

#include <libwebsockets.h>

#include <time.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

int ws_http_serve_interpret_retcode(struct lws *wsi, int ret)
{
	if (ret < 0) {
		lwsl_info("error %d serving file\n", ret);
		return -1;
	} else if (ret > 0) {
		return lws_http_transaction_completed(wsi);
	}
	lwsl_debug("not closing connection\n");
	return 0;
}

static char *ws_http_construct_pathname(const char *base, const char *in)
{
	char *filepath = malloc(PATH_MAX);
	int written = snprintf(filepath, PATH_MAX, "%s/%s%s",
			base, in, in[strlen(in)-1] == '/' ? "index.html" : "");
	if (written < 0) {
		free(filepath);
		return NULL;
	} else if (written >= PATH_MAX) {
		filepath = realloc(filepath, (size_t)written);
		snprintf(filepath, PATH_MAX, "%s/%s%s",
				base, in, in[strlen(in)-1] == '/' ? "index.html" : "");
	}

	return filepath;
}

struct fileext_map {
	const char *ext;
	const char *val;
};

static const char * filepath_strnrchr(const char *filepath, size_t n, int c)
{
	const char *last_dot = filepath + n - 1;
	while (last_dot >= filepath && *last_dot != c) {
		--last_dot;
	}
	if (last_dot >= filepath)
		return last_dot;

	return NULL;
}

static const struct fileext_map* mapping_by_extension(const char *ext, size_t n,
		const struct fileext_map map[], size_t map_size)
{
	for (const struct fileext_map *end = map + map_size; map < end; ++map) {
		if (!strncasecmp(ext, map->ext, n))
			return map;
	}

	return NULL;
}

static const char *determine_mimetype(const char *filepath, size_t n)
{
	static const struct fileext_map mime_map[] = {
		{ "html", "text/html"                 },
		{ "js"  , "application/javascript"    },
		{ "png" , "image/png"                 },
		{ "gif" , "image/gif"                 },
		{ "jpg" , "image/jpeg"                },
		{ "jpeg", "image/jpeg"                },
		{ "css" , "text/css"                  },
		{ "txt" , "text/plain"                },
		{ "htm" , "text/html"                 },
		{ "bin" , "application/octet-stream"  },
		{ "img" , "application/octet-stream"  },
	};

	const char *last_dot = filepath_strnrchr(filepath, n, '.');
	if (last_dot) {
		size_t ext_len = (size_t)(filepath + n - last_dot) - 1;
		const struct fileext_map *m = mapping_by_extension(last_dot+1, ext_len, mime_map, ARRAY_SIZE(mime_map));
		if (m) {
			return m->val;
		}
	}

	return NULL;
}

struct file_meta {
	int status;
	struct stat filestat;

	char *real_filepath;

	const char *mime;
	const char *enc;

	unsigned char headers[1024];
	unsigned char *headers_cur;
};

#define foreach_strtoken(cur, hdr, delim) \
	for (char *cur = hdr, *ctx##cur; \
			(cur = strtok_r(cur, delim, &ctx##cur)) != NULL; \
			cur = NULL)

static void determine_file_meta(struct lws *wsi, struct file_meta *meta, char *filepath, size_t n)
{
	static const struct fileext_map enc_map[] = {
		{ "br", "brotli"  },
		{ "gz", "gzip"    },
		{ "zz", "deflate" },
	};

	(void)wsi;

	meta->real_filepath = malloc(n + 4);
	strncpy(meta->real_filepath, filepath, n+1);
	free(filepath);

	const char *mime = determine_mimetype(meta->real_filepath, n);
	meta->mime = mime ? mime : "application/octet-stream";
	meta->enc = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(enc_map); ++i) {
		strcat(meta->real_filepath, ".");
		strcat(meta->real_filepath, enc_map[i].ext);
		if (0 == access(meta->real_filepath, R_OK)) {
			// we don't consult accept_encoding header since we might not have non-encoded file
			meta->enc = enc_map[i].val;
			break;
		}
		meta->real_filepath[n] = '\0';
	}

	meta->status = stat(meta->real_filepath, &meta->filestat);
}

static const char *const http_timestr = "%a, %d %b %Y %H:%M:%S %Z";

static void add_last_modified_header(struct lws *wsi, struct file_meta *meta)
{
	char buf[256];
	strftime(buf, sizeof buf, http_timestr,
			gmtime(&meta->filestat.st_mtime));

	lwsl_debug("timestamp of %s is %s\n", meta->real_filepath, buf);

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LAST_MODIFIED, (const unsigned char*)buf, (int)strlen(buf), &meta->headers_cur, meta->headers + sizeof meta->headers)) {
		lwsl_err("Couldn't add Last-modified headers!\n");
	}
}

static bool can_reply_notmodified(struct lws *wsi, struct file_meta *meta)
{
	if (meta->status) {
		lwsl_debug("file doesn't exist, not doing 304: %d\n", meta->status);
		return false;
	}

	char buf[256] = "";

	lws_hdr_copy(wsi, buf, sizeof buf - 1, WSI_TOKEN_HTTP_CACHE_CONTROL);

	foreach_strtoken (cur, buf, ",; ") {
		if (!strcmp(cur, "no-cache") || cur == strstr(cur, "no-cache=")) {
			lwsl_debug("no-cache found, don't do 304\n");
			return false;
		}
	}

	buf[0] = '\0';

	lws_hdr_copy(wsi, buf, sizeof buf - 1, WSI_TOKEN_HTTP_IF_MODIFIED_SINCE);

	struct tm tm = {};
	char *p = strptime(buf, http_timestr, &tm);
	if (!p || p < buf + strlen(buf) - 4) {
		lwsl_debug("could not parse if-mod-since %s as time: %s\n", buf, p ? "nonwhole offset" : "NULL ret");
		return false;
	}

	time_t iftime = mktime(&tm);
	time_t file_mtime = meta->filestat.st_mtime;

	return file_mtime <= iftime;
}

int ws_http_serve_file(struct lws *wsi, const char *in)
{
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	char *filepath = ws_http_construct_pathname(prog->www_path, in);
	size_t len = strlen(filepath);

	struct file_meta meta = { .status = -1 };
	meta.headers_cur = meta.headers;
	determine_file_meta(wsi, &meta, filepath, len);
	lwsl_info("http request for %s = file %s\n", in, meta.real_filepath);

	int rc;
	if (prog->redir_from && !strcmp(in, prog->redir_from)) {
		// redirect
		if ((rc = lws_http_redirect(wsi, HTTP_STATUS_SEE_OTHER, (const unsigned char*)prog->redir_to, strlen(prog->redir_to), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if ((rc = lws_finalize_http_header(wsi, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		rc = lws_write(wsi, meta.headers, (size_t)(meta.headers_cur - meta.headers), LWS_WRITE_HTTP_HEADERS);
	} else if (can_reply_notmodified(wsi, &meta)) {
		lwsl_debug("could reply 304...\n");
		if ((rc = lws_add_http_header_status(wsi, 304, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if (meta.enc && (rc = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (const unsigned char*)meta.enc, (int)strlen(meta.enc), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if ((rc = lws_finalize_http_header(wsi, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		rc = lws_write(wsi, meta.headers, (size_t)(meta.headers_cur - meta.headers), LWS_WRITE_HTTP_HEADERS);
	} else {
		if (meta.enc && (rc = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (const unsigned char*)meta.enc, (int)strlen(meta.enc), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if (meta.status) {
			lwsl_debug("file doesn't exist, not putting timestamp in header: %d\n", meta.status);
			rc = lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
			goto out;
		}

		add_last_modified_header(wsi, &meta);
		rc = lws_serve_http_file(wsi, meta.real_filepath, meta.mime, (const char*)meta.headers, (int)(meta.headers_cur - meta.headers));
	}
out:
	free(meta.real_filepath);
	return ws_http_serve_interpret_retcode(wsi, rc);
}
