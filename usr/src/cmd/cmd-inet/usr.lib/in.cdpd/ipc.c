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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "yuka.h"
#include "cdp.h"
#include "cmd.h"

extern int verbose;

static void
yuka_handle_ipc(int fd)
{
	struct pollfd pollfds[] = {
		{ .fd = fd, .events = POLLIN }
	};
	char buf[1024], *cmd;
	int argc, fflag, i;

	if (verbose > 1)
		printf("handle_ipc for FD: %d\n", fd);

	i = poll(pollfds, 1, 3000);

	if (i == 0) {
		if (verbose)
			printf("IPC timeout.\n");
		return;
	}

	if (i == -1) {
		perror("IPC poll");
		return;
	}

	argc = recv(fd, buf, 1024, 0);

	if (argc < 2) {
		printf("IPC: short read, %d\n", argc);
		return;
	}

	if (verbose > 3) {
		printf("ipc-recv:\n");
		xdump((uint8_t *)buf, argc);
	}

	fflag = buf[0];
	cmd = buf + 1;
	argc -= 2;

	switch (cmd[0]) {

	case YUKA_CMD_REAP:
		yuka_cdp_reap(0);
		break;

	case YUKA_CMD_SHOW:
		if (argc < 2) {
			yuka_show_cdp_hosts(fd, fflag);
			break;
		}

		switch (cmd[1]) {
		case YUKA_CMD_SHOW_CDP:
			yuka_show_cdp_hosts(fd, fflag);
			break;
		case YUKA_CMD_SHOW_DETAIL:
			yuka_show_detail(fd);
			break;
		default:
			(void) write(fd, "Command Error\n", 14);
			break;
		}
		break;

	case YUKA_CMD_STATS:
		yuka_stats(fd);
		break;

	default:
		(void) write(fd, "Unknown command\n", 16);
		break;
	}
}

static void *
ipc_thread(void *xfd)
{
	int fd = (int)(uintptr_t)xfd;

	(void) pthread_setname_np(pthread_self(), "ipc");

	if (verbose)
		printf("IPC thread starting\n");

	for (;;) {
		struct pollfd pollfds[] = {
			{ .fd = fd, .events = POLLIN }
		};

		if (poll(pollfds, 1, -1) <= 0)
			break;

		if (pollfds[0].revents & POLLIN) {
			struct sockaddr_un addr;
			socklen_t addrlen = sizeof (addr);
			int c = accept4(fd, (struct sockaddr *)&addr, &addrlen,
			    SOCK_NDELAY | SOCK_NONBLOCK);

			if (c == -1) {
				printf("Control socket accept failed, %s\n",
				    strerror(errno));
				continue;
			}

			if (verbose)
				printf("New IPC connection.\n");

			yuka_handle_ipc(c);
			(void) close(c);
		}
	}
	(void) close(fd);
	(void) unlink(YUKA_SOCKET);

	return (NULL);
}

int
init_ipc_socket(void)
{
	struct sockaddr_un server;
	int fd;

	memset(&server, 0, sizeof (server));
	server.sun_family = AF_UNIX;
	(void) strlcpy(server.sun_path, YUKA_SOCKET, sizeof (server.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("ipc: socket()");
		return (-1);
	}

	if (bind(fd, (struct sockaddr *)&server, sizeof (server)) == -1) {
		if (errno == EADDRINUSE) {
			/* See if the socket is still live */

			if (connect(fd, (struct sockaddr *) &server,
			    sizeof (server)) >= 0) {
				printf("Control socket is in use by another "
				    "process.\n");
				goto err;
			}

			/* If not, clean it up */

			if (unlink(server.sun_path) == -1) {
				printf("Could not unlink stale control "
				    "socket, %s\n", strerror(errno));
				goto err;
			}

			/* Try and bind again */

			if (bind(fd, (struct sockaddr *)&server,
			    sizeof (server)) == -1) {
				printf("Cannot bind to control socket, %s\n",
				    strerror(errno));
				goto err;
			}
		} else {
			printf("Cannot bind to control socket, %s\n",
			    strerror(errno));
			goto err;
		}
	}

	if (fchmod(fd, 0444)) {
		perror("ipc: fchmod");
		goto err;
	}

	if (listen(fd, 10)) {
		perror("ipc: listen");
		goto err;
	}

	return (fd);

err:
	(void) close(fd);
	return (-1);
}

int
init_ipc(void)
{
	pthread_t tid;
	int fd;

	if ((fd = init_ipc_socket()) == -1)
		return (0);

	if (pthread_create(&tid, NULL, ipc_thread, (void *)(uintptr_t)fd)
	    == 0 && pthread_detach(tid) == 0) {
		return (1);
	}

	(void) close(fd);
	return (0);
}

void
deinit_ipc(int fd)
{
	(void) close(fd);
	if (unlink(YUKA_SOCKET) < 0)
		perror("deinit-ipc: unlink()");
}
