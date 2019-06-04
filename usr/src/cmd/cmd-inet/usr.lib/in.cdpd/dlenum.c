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

#include "yuka.h"
#include <libdladm.h>
#include <libdllink.h>

static char linkname[MAXLINKNAMELEN];

static int
list_link(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	uint32_t flags;
	dladm_status_t status;
	datalink_class_t class;
	uint32_t media;

	if ((status = dladm_datalink_id2info(dh, linkid, &flags, &class,
	    &media, linkname, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}
	printf("Link: %s, class: 0x%x, flags: 0x%x, media: 0x%x\n",
	    linkname, class, flags, media);

	return (DLADM_WALK_CONTINUE);
}

void
yuka_list_links(void)
{
	dladm_handle_t h;
	dladm_status_t status;

	if ((status = dladm_open(&h)) != DLADM_STATUS_OK) {
		perror("could not enumerate datalinks");
		fprintf(stderr, "Error code: %d\n", status);
		exit(1);
	}
	(void) dladm_walk_datalink_id(list_link, h, NULL,
		DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	dladm_close(h);
}

static int
getlist_link(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	uint32_t flags;
	dladm_status_t status;
	datalink_class_t class;
	uint32_t media;
	stringlist_t *s, **lp;

	lp = (stringlist_t **)arg;

	if ((status = dladm_datalink_id2info(dh, linkid, &flags, &class,
	    &media, linkname, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}
	s = malloc(sizeof (stringlist_t));
	if (s == NULL) {
		fprintf(stderr, "Out of memory\n");
		return (DLADM_WALK_TERMINATE);
	}
	s->str = strdup(linkname);
	s->next = *lp;
	*lp = s;
	return (DLADM_WALK_CONTINUE);
}

void
yuka_get_links(stringlist_t **slist)
{
	dladm_handle_t h;
	dladm_status_t status;

	if ((status = dladm_open(&h)) != DLADM_STATUS_OK) {
		perror("could not enumerate datalinks");
		fprintf(stderr, "Error code: %d\n", status);
		exit(1);
	}

	(void) dladm_walk_datalink_id(getlist_link, h, slist,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	dladm_close(h);
}

void
yuka_free_links(stringlist_t *slist)
{
	while (slist != NULL) {
		stringlist_t *next = slist->next;
		free(slist->str);
		free(slist);
		slist = next;
	}
}
