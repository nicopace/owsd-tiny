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
#pragma once

struct lws;

/**
 * \brief respond to plain HTTP request by serving HTTP file
 *
 * \param wsi client
 * \param in path component
 */
int ws_http_serve_file(struct lws *wsi, const char *in);

/**
 * \brief based on state of client, and return code from libwebsockets calls,
 * determine what code to return to libwebsockets, i.e. whether we should close
 * the connection or continue
 *
 * \param wsi client
 * \param ret return code of libwebsockets functions
 */
int ws_http_serve_interpret_retcode(struct lws *wsi, int ret);
