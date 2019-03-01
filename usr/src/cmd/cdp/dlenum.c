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
 */
#include "yuka.h"
#include <libdladm.h>
#include <libdllink.h>

static char linkname[MAXLINKNAMELEN];

struct list_state {
	struct yuka_string_list * first;
	struct yuka_string_list * last;
};

static int
list_link(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	uint32_t flags;
	dladm_status_t status;
	datalink_class_t class;
	uint32_t media;

	if( (status = dladm_datalink_id2info(dh, linkid, &flags, &class,
		&media, linkname, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return status;
	}
	printf("Link: %s, class: 0x%x, flags: 0x%x, media: 0x%x\n", linkname, class, flags, media);
	return DLADM_WALK_CONTINUE;
}

void
yuka_list_links()
{
	dladm_handle_t h;
	dladm_status_t status;

	if( (status = dladm_open(&h)) != DLADM_STATUS_OK ) {
		perror("could not enumerate datalinks");
		fprintf(stderr, "Error code: %d\n", status);
		exit(1);
	}
	dladm_walk_datalink_id(list_link, h, NULL,
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
	struct list_state *lst = (struct list_state*)arg;

	if( (status = dladm_datalink_id2info(dh, linkid, &flags, &class,
		&media, linkname, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return status;
	}
	if(!lst->last) {
		lst->last = lst->first = (struct yuka_string_list*)malloc(sizeof(struct yuka_string_list));
	} else {
		lst->last->next = (struct yuka_string_list*)malloc(sizeof(struct yuka_string_list));
		lst->last = lst->last->next;
	}
	lst->last->next = NULL;
	lst->last->str = strdup(linkname);
	return DLADM_WALK_CONTINUE;
}

void
yuka_get_links(struct yuka_string_list ** slist)
{
	dladm_handle_t h;
	dladm_status_t status;
	struct list_state lst;
	lst.first = NULL;
	lst.last = NULL;

	if( (status = dladm_open(&h)) != DLADM_STATUS_OK ) {
		perror("could not enumerate datalinks");
		fprintf(stderr, "Error code: %d\n", status);
		exit(1);
	}
	dladm_walk_datalink_id(getlist_link, h, &lst,
		DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	dladm_close(h);
	if(slist) {
		*slist = lst.first;
	}
}

void
yuka_free_links(struct yuka_string_list *slist)
{
	while(slist) {
		struct yuka_string_list *next;
		next = slist->next;
		free(slist->str);
		free(slist);
		slist = next;
	}
}

