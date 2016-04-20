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

#pragma once

struct lws;

int ws_http_serve_file(struct lws *wsi, const char *in);
int ws_http_serve_interpret_retcode(struct lws *wsi, int ret);
