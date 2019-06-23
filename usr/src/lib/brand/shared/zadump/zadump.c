/*
 * {{{ CDDL HEADER
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 * }}}
 */

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libdladm.h>
#include <libdllink.h>
#include <zone.h>

static zoneid_t zoneid;

char *
strattr(int attr)
{
	static char buf[MAXPATHLEN];

	if (zone_getattr(zoneid, attr, buf, sizeof (buf)) < 0)
		return (strerror(errno));
	return (buf);
}

void
zone_get_network(datalink_id_t linkid, int type, char *buf, size_t *bufsize)
{
	zone_net_data_t *zndata;

	zndata = calloc(1, sizeof (*zndata) + *bufsize);
	assert(zndata != NULL);

	zndata->zn_type = type;
	zndata->zn_linkid = linkid;
	zndata->zn_len = *bufsize;

	if (zone_getattr(zoneid, ZONE_ATTR_NETWORK, zndata,
	    sizeof (*zndata) + *bufsize) < 0) {
		*bufsize = 0;
		free(zndata);
		return;
	}
	*bufsize = zndata->zn_len;
	bcopy(zndata->zn_val, buf, *bufsize);
	free(zndata);
}

#define	LABEL "%-20s: "

int
show_datalink(dladm_handle_t handle, datalink_id_t linkid,
    void *arg __unused)
{
	char buf[PIPE_BUF], link[MAXLINKNAMELEN];
	size_t bufsize;

	if (dladm_datalink_id2info(handle, linkid, NULL, NULL, NULL,
	    link, sizeof (link)) != DLADM_STATUS_OK)
		(void) strlcpy(link, "??", MAXLINKNAMELEN);
	printf(LABEL "%d - %s\n", "Datalink", linkid, link);

	bufsize = sizeof (buf);
	bzero(buf, bufsize);
	zone_get_network(linkid, ZONE_NETWORK_ADDRESS, buf, &bufsize);
	if (bufsize > 0)
		printf(LABEL "    [%s]\n", "    address", buf);

	bufsize = sizeof (buf);
	bzero(buf, bufsize);
	zone_get_network(linkid, ZONE_NETWORK_DEFROUTER, buf, &bufsize);
	if (bufsize > 0) {
		struct in6_addr defrouter;
		char gw[INET6_ADDRSTRLEN + 1];

		bcopy(buf, &defrouter, sizeof (defrouter));
		if (IN6_IS_ADDR_V4MAPPED(&defrouter)) {
			struct in_addr gw4;
			IN6_V4MAPPED_TO_INADDR(&defrouter, &gw4);
			(void) inet_ntop(AF_INET, &gw4, gw, sizeof (gw));
		} else {
			(void) inet_ntop(AF_INET6, &defrouter, gw, sizeof (gw));
		}
		printf(LABEL "    [%s]\n", "    router", gw);
	}

	return (DLADM_WALK_CONTINUE);
}

int
usage(void)
{
	fprintf(stderr, "Syntax: zadump [zoneid]\n");
	return (1);
}

int
main(int argc, char **argv)
{
	zone_status_t status;
	char *statusname;
	ushort_t flags;
	int initpid;
	uint64_t uniqid;

	if (argc == 2) {
		zoneid = atoi(argv[1]);
		if (zoneid <= 0)
			return (usage());
	} else if (argc == 1) {
		zoneid = getzoneid();
	} else {
		return (usage());
	}

	printf(LABEL "%s\n", "Name", strattr(ZONE_ATTR_NAME));
	if (zone_getattr(zoneid, ZONE_ATTR_UNIQID,
	    &uniqid, sizeof (uniqid)) < 0)
		uniqid = 0;
	printf(LABEL "%llu\n", "Unique ID", uniqid);
	printf(LABEL "%s\n", "Root", strattr(ZONE_ATTR_ROOT));
	printf(LABEL "%s\n", "Brand", strattr(ZONE_ATTR_BRAND));
	printf(LABEL "%s\n", "Boot args", strattr(ZONE_ATTR_BOOTARGS));
	printf(LABEL "%s\n", "Allowed FS", strattr(ZONE_ATTR_FS_ALLOWED));

	if (zone_getattr(zoneid, ZONE_ATTR_STATUS,
	    &status, sizeof (status)) < 0) {
		status = 0;
		statusname = "Unknown";
	} else {
		switch (status) {
		case ZONE_IS_UNINITIALIZED:
			statusname = "Uninitialised";
			break;
		case ZONE_IS_INITIALIZED:
			statusname = "Initialised";
			break;
		case ZONE_IS_READY:
			statusname = "Ready";
			break;
		case ZONE_IS_BOOTING:
			statusname = "Booting";
			break;
		case ZONE_IS_RUNNING:
			statusname = "Running";
			break;
		case ZONE_IS_SHUTTING_DOWN:
			statusname = "Shutting down";
			break;
		case ZONE_IS_EMPTY:
			statusname = "Empty";
			break;
		case ZONE_IS_DOWN:
			statusname = "Down";
			break;
		case ZONE_IS_DYING:
			statusname = "Dying";
			break;
		case ZONE_IS_DEAD:
			statusname = "Dead";
			break;
		default:
			statusname = "Unknown";
			break;
		}
	}
	printf(LABEL "%d (%s)\n", "Status", status, statusname);

	if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags, sizeof (flags)) < 0)
		flags = 0;
	printf(LABEL "%x (", "Flags", flags);
	if (flags & ZF_REFCOUNTS_LOGGED)
		printf("Refcounts,");
	if (flags & ZF_HASHED_LABEL)
		printf("Label,");
	if (flags & ZF_IS_SCRATCH)
		printf("Scratch,");
	if (flags & ZF_NET_EXCL)
		printf("Exclusive,");
	printf(")\n");

	if (zone_getattr(zoneid, ZONE_ATTR_INITPID,
	    &initpid, sizeof (initpid)) < 0)
		initpid = 1;
	printf(LABEL "%s\n", "Init Name", strattr(ZONE_ATTR_INITNAME));
	printf(LABEL "%d\n", "Init PID", initpid);

	dladm_handle_t handle;

	if (flags & ZF_NET_EXCL) {
		if (dladm_open(&handle) == DLADM_STATUS_OK) {
			(void) dladm_walk_datalink_id(show_datalink,
			    handle, NULL,
			    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_PERSIST | DLADM_OPT_ACTIVE);
			dladm_close(handle);
		}
	}

	return (0);
}

/*
 * vim:fdm=marker
 */
