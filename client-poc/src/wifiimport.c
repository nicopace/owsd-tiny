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

#include "wifiimport.h"

#include <json-c/json_object.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>

#include "common.h"

static pid_t child_pid = 0;

void sigchld_handler(int signum)
{
	int status;
	if (child_pid == waitpid(child_pid, &status, WNOHANG)) {
		fprintf(stderr, "child %d exited\n", child_pid);
		child_pid = 0;
	}
}

int exec_wifi_import(struct json_object *cred_data)
{

	signal(SIGCHLD, sigchld_handler);

	if (child_pid || 0 > (child_pid = fork())) {
		return child_pid;
	} else if (child_pid) {
		return 0;
	} else {
		char * const argv[] = {"wifi", "import", (char*)json_object_to_json_string(cred_data), NULL};
		exit(execv(argv[0], argv));
	}
}
