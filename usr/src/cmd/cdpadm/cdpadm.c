/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2015, 2018, 2019, Meisaka Yukara
 * Copyright 2018, 2019 Prominic.NET Inc. All Rights reserved.
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include "../cmd-inet/usr.lib/in.cdpd/cmd.h"

typedef struct yuka_command {
	const char *name;
	uint8_t code;
	struct yuka_command *sub;
} cmd_t;

static cmd_t yuka_show_commands[] = {
	{ "cdp",	YUKA_CMD_SHOW_CDP,	NULL },
	{ "nei",	YUKA_CMD_SHOW_CDP,	NULL },
	{ "detail",	YUKA_CMD_SHOW_DETAIL,	NULL },
	{ NULL,		0,			NULL }
};

static cmd_t yuka_commands[] = {
	{ "show",	YUKA_CMD_SHOW,		yuka_show_commands },
	{ "reap",	YUKA_CMD_REAP,		NULL },
	{ "stats",	YUKA_CMD_STATS,		NULL },
	{ NULL,		0,			NULL }
};

static cmd_t *
search_commands(char *cmd, cmd_t *cmdlist)
{
	for (; cmdlist->name != NULL; cmdlist++) {
		if (strcmp(cmd, cmdlist->name) == 0)
			return (cmdlist);
	}
	return (NULL);
}

static int
connect_ipc(void)
{
	int ufd;
	struct sockaddr_un server;

	memset(&server, 0, sizeof (server));
	server.sun_family = AF_UNIX;
	(void) strlcpy(server.sun_path, YUKA_SOCKET, sizeof (server.sun_path));

	if ((ufd = socket(server.sun_family, SOCK_STREAM, 0)) == -1) {
		perror("ipc: socket()");
		return (-1);
	}

	if (connect(ufd, (struct sockaddr *)&server, sizeof (server)) == -1) {
		if (errno == ENOENT || errno == ECONNREFUSED)
			fprintf(stderr, "The CDP service is not running.\n");
		else
			perror("ipc: connect()");
		(void) close(ufd);
		return (-1);
	}
	return (ufd);
}

static void
close_ipc(int fd)
{
	(void) close(fd);
}

static int
write_fd(int fd, unsigned char *ptr, int len)
{
	struct pollfd pollfds[] = {
		{ .fd = fd, .events = POLLOUT }
	};

	if (poll(pollfds, 1, YUKA_CLIENT_TIMEOUT) <= 0 ||
	    (pollfds[0].revents & POLLOUT) == 0)
		return (-1);

	return (write(fd, ptr, len));
}

static boolean_t
is_readable(int fd)
{
	struct pollfd pollfds[] = {
		{ .fd = fd, .events = POLLIN }
	};

	if (poll(pollfds, 1, YUKA_CLIENT_TIMEOUT) <= 0 ||
	    (pollfds[0].revents & POLLIN) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

static void
usage(void)
{
	cmd_t *cmd;

	(void) fprintf(stderr,
	    "Usage:  cdp [-f <format>] <command> <args> ...\n");

	for (cmd = yuka_commands; cmd->name != NULL; cmd++) {
		int flag;
		cmd_t *scmd;

		fprintf(stderr, "    %s", cmd->name);
		if (cmd->sub) {
			flag = 0;
			fprintf(stderr, " [");
			for (scmd = cmd->sub; scmd->name != NULL; scmd++) {
				if (flag)
					fprintf(stderr, "|");
				fprintf(stderr, scmd->name);
				flag++;
			}
			fprintf(stderr, "]");
		}
		fprintf(stderr, "\n");
	}

	fprintf(stderr, "Available formats: text, parse, json, xml\n");
}

static const struct option lopts[] = {
	{"format",		required_argument,	NULL, 'f'},
	{NULL,			0,			NULL, '\0'}
};

int
main(int argc, char **argv)
{
	int fd, i;
	char oc;
	cmd_t *cmdlist, *cmd;
	uint8_t fflag = YUKA_FMT_TEXT;
	uint8_t sendcmd[5];
	uint8_t *c = sendcmd;

	while ((oc = getopt_long(argc, argv, ":f:", lopts, NULL)) != EOF) {
		switch (oc) {
		case 'f':
			if (strcmp(optarg, "x") == 0 ||
			    strcmp(optarg, "xml") == 0)
				fflag = YUKA_FMT_XML;
			else if (strcmp(optarg, "j") == 0 ||
			    strcmp(optarg, "json") == 0)
				fflag = YUKA_FMT_JSON;
			else if (strcmp(optarg, "p") == 0 ||
			    strcmp(optarg, "parse") == 0)
				fflag = YUKA_FMT_PARSE;
			else
				fflag = YUKA_FMT_TEXT;
			break;
		default:
			switch (oc) {
			case ':':
				fprintf(stderr,
				    "option '-%c' requires a value.\n",
				    optopt);
				break;
			case '?':
				fprintf(stderr,
				    "unrecognised option '-%c'.\n",
				    optopt);
				break;
			}
			usage();
			return (0);
		}
	}

	if (optind == argc) {
		usage();
		return (0);
	}

	cmdlist = yuka_commands;
	*c++ = fflag;
	for (i = optind; i < argc; i++) {
		if ((cmd = search_commands(argv[i], cmdlist)) == NULL) {
			usage();
			return (0);
		}
		*c++ = cmd->code;
		if (cmd->sub != NULL)
			cmdlist = cmd->sub;
	}
	*c++ = '\0';

	if ((fd = connect_ipc()) == -1)
		return (1);

	if (write_fd(fd, sendcmd, c - sendcmd) < 0) {
		fprintf(stderr, "Error sending command, %s.\n",
		    strerror(errno));
	} else {
		char buf[0x400];

		(void) shutdown(fd, SHUT_WR);

		while (is_readable(fd)) {
			i = read(fd, buf, sizeof (buf));
			if (i <= 0)
				break;
			buf[i] = '\0';
			printf("%s", buf);
		}
	}

	close_ipc(fd);

	return (0);
}
