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
		// close unconditionally if return code from lws is bad
		return -1;
	} else if (ret > 0) {
		// return code is okay, ask lws if transaction is done, and return
		// accordingly. This will make us stay connected on HTTP/1.1 and close
		// on HTTP/1.0 etc.
		return lws_http_transaction_completed(wsi) ? -1 : 0;
	}
	// return code is "neutral", keep connection alive
	lwsl_debug("not closing connection\n");
	return 0;
}

/**
 * \brief concatenates base directory path with requested path. Note that we
 * don't have to worry about ../ in requested path since lws itself bans this
 * from requested path.
 */
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

/*
 * Following structs and functions are to enable having and serving only
 * gzipped content on disk to save space.  When client asks for file.ext.gx, we
 * give him "file" with content-type corresponding to extension "ext", and
 * content-encoding corresponding to extension "gx"
 */

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
        const struct fileext_map *m = mapping_by_extension(last_dot+1, ext_len, mime_map, LWS_ARRAY_SIZE(mime_map));
		if (m) {
			return m->val;
		}
	}

	return NULL;
}

/**
 * \brief holds information about content-type, encoding, real file path (in
 * case we are serving a compressed file), as well as date/time info for cache
 * headers
 */
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

/**
 * \brief Fills in meta structure
 */
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

	// determine what would be the mimetype of the wanted file by extension
	const char *mime = determine_mimetype(meta->real_filepath, n);
	meta->mime = mime ? mime : "application/octet-stream";
	meta->enc = NULL;

	// add extensions from list until we find one that exists on disk
    for (size_t i = 0; i < LWS_ARRAY_SIZE(enc_map); ++i) {
		strcat(meta->real_filepath, ".");
		strcat(meta->real_filepath, enc_map[i].ext);
		if (0 == access(meta->real_filepath, R_OK)) {
			// success, we store encoding type in meta struct

			// TODO we don't consult accept_encoding header since we might not have non-encoded file
			// we should have some logic to uncompress the file, or look for a non-compressed file if client doesnt support that content encoding
			// TODO even better, get rid of this whole file and use all generic mechanisms from libwebsockets itself
			// - cache and tweaks are possible
			// - redirection rule may or may not be possible
			// - uncompression should definitely be possible since v2.2
			meta->enc = enc_map[i].val;
			break;
		}
		meta->real_filepath[n] = '\0';
	}

	meta->status = stat(meta->real_filepath, &meta->filestat);
}

static const char *const http_timestr = "%a, %d %b %Y %H:%M:%S %Z";

/**
 * \brief add header using date time info from file's metadata
 */
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

/**
 * \brief determine if file and client's cache-related headers are okay to just
 * reply with 304 not modified
 */
static bool can_reply_notmodified(struct lws *wsi, struct file_meta *meta)
{
	if (meta->status) {
		lwsl_debug("file doesn't exist, not doing 304: %d\n", meta->status);
		return false;
	}

	char buf[256] = "";

	lws_hdr_copy(wsi, buf, sizeof buf - 1, WSI_TOKEN_HTTP_CACHE_CONTROL);

	// check cache-control header for mention of no-cache
	foreach_strtoken (cur, buf, ",; ") {
		if (!strcmp(cur, "no-cache") || cur == strstr(cur, "no-cache=")) {
			lwsl_debug("no-cache found, don't do 304\n");
			return false;
		}
	}

	buf[0] = '\0';

	lws_hdr_copy(wsi, buf, sizeof buf - 1, WSI_TOKEN_HTTP_IF_MODIFIED_SINCE);

	// check file's date is after if-modified-since
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

	// read file datetime, mime, ...
	determine_file_meta(wsi, &meta, filepath, len);
	lwsl_info("http request for %s = file %s\n", in, meta.real_filepath);

	int rc;
	if (prog->redir_from && !strcmp(in, prog->redir_from)) {
		// request matches a url for which we have a redirect option

		// in that case just do a redirect
		if ((rc = lws_http_redirect(wsi, HTTP_STATUS_SEE_OTHER, (const unsigned char*)prog->redir_to, strlen(prog->redir_to), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if ((rc = lws_finalize_http_header(wsi, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		rc = lws_write(wsi, meta.headers, (size_t)(meta.headers_cur - meta.headers), LWS_WRITE_HTTP_HEADERS);
	} else if (can_reply_notmodified(wsi, &meta)) {
		// otherwise check if we can tell client to get it from their cache

		lwsl_debug("could reply 304...\n");
		if ((rc = lws_add_http_header_status(wsi, 304, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if (meta.enc && (rc = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (const unsigned char*)meta.enc, (int)strlen(meta.enc), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if ((rc = lws_finalize_http_header(wsi, &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		rc = lws_write(wsi, meta.headers, (size_t)(meta.headers_cur - meta.headers), LWS_WRITE_HTTP_HEADERS);
	} else {
		// default, just serve the file

		if (meta.enc && (rc = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (const unsigned char*)meta.enc, (int)strlen(meta.enc), &meta.headers_cur, meta.headers + sizeof meta.headers)))
			goto out;
		if (meta.status) {
			lwsl_debug("file doesn't exist, not putting timestamp in header: %d\n", meta.status);
			rc = !lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL) ? 1 : -1;
			goto out;
		}

		add_last_modified_header(wsi, &meta);
		rc = lws_serve_http_file(wsi, meta.real_filepath, meta.mime, (const char*)meta.headers, (int)(meta.headers_cur - meta.headers));
	}
out:
	free(meta.real_filepath);
	return ws_http_serve_interpret_retcode(wsi, rc);
}
