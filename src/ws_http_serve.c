#include "ws_http_serve.h"
#include "common.h"

#include <libwebsockets.h>


int ws_http_serve_interpret_retcode(struct lws *wsi, int ret)
{
	if (ret < 0) {
		lwsl_info("error %d serving file\n", ret);
		return -1;
	} else if (ret > 0) {
		return lws_http_transaction_completed(wsi);
	}
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

static const struct fileext_map enc_map[] = {
	{ "br", "brotli"  },
	{ "gz", "gzip"    },
	{ "zz", "deflate" },
};

static const char *determine_mimetype(const char *filepath, size_t n)
{
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
	char *real_filepath;
	const char *mime;
	unsigned char headers[1024];
	unsigned char *headers_cur;
};

static void determine_file_meta(struct lws *wsi, struct file_meta *meta, char *filepath, size_t n)
{
#if 0
	char accept_encoding_header[2048];
	int accept_len = lws_hdr_copy(wsi, accept_encoding_header, sizeof accept_encoding_header, WSI_TOKEN_HTTP_ACCEPT_ENCODING);

	lwsl_info("client accepts encoding %.*s\n", accept_len, accept_encoding_header);
#endif // TODO use this

	meta->real_filepath = malloc(n + 4);
	strncpy(meta->real_filepath, filepath, n+1);
	free(filepath);

	const char *mime = determine_mimetype(meta->real_filepath, n);
	meta->mime = mime ? mime : "application/octet-stream";

	for (size_t i = 0; i < ARRAY_SIZE(enc_map); ++i) {
		strcat(meta->real_filepath, ".");
		strcat(meta->real_filepath, enc_map[i].ext);
		if (0 == access(meta->real_filepath, R_OK)) {
			// TODO also consult accept_encoding header
			lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (const unsigned char*)enc_map[i].val, (int)strlen(enc_map[i].val), &meta->headers_cur, meta->headers + sizeof meta->headers);
			break;
		}
		meta->real_filepath[n] = '\0';
	}
}

int ws_http_serve_file(struct lws *wsi, const char *in) {
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	char *filepath = ws_http_construct_pathname(prog->www_path, in);
	size_t len = strlen(filepath);

	struct file_meta meta = {NULL, NULL, "", NULL};
	meta.headers_cur = meta.headers;
	determine_file_meta(wsi, &meta, filepath, len);

	lwsl_info("http request for %s = file %s\n", in, meta.real_filepath);

	int rc = lws_serve_http_file(wsi, meta.real_filepath, meta.mime, (const char*)meta.headers, (int)(meta.headers_cur - meta.headers));
	free(meta.real_filepath);
	return ws_http_serve_interpret_retcode(wsi, rc);
}
