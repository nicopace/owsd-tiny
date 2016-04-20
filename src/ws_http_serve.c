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

static const struct {
	const char *ext;
	const char *mime;
} mime_mapping[] = {
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

static const char *determine_mimetype(const char *filepath, size_t n)
{
	const char *last_dot = filepath + n - 1;
	while (last_dot >= filepath && *last_dot != '.') {
		--last_dot;
	}

	if (last_dot >= filepath) {
		size_t n2 = (size_t)(filepath + n - last_dot) - 1;
		for (size_t i = 0; i < ARRAY_SIZE(mime_mapping); ++i) {
			if (!strncasecmp(last_dot+1, mime_mapping[i].ext, n2))
				return mime_mapping[i].mime;
		}
	}
	return ""; // TODO default mimetype?
}

int ws_http_serve_file(struct lws *wsi, const char *in) {
	struct prog_context *prog = lws_context_user(lws_get_context(wsi));
	char *filepath = ws_http_construct_pathname(prog->www_path, in);
	lwsl_info("http request, giving file %s\n", filepath);

	int rc = lws_serve_http_file(wsi, filepath, determine_mimetype(filepath, strlen(filepath)), NULL, 0);
	free(filepath);
	return ws_http_serve_interpret_retcode(wsi, rc);
}
