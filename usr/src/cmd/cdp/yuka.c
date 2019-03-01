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
/*
 * yuka - datalink gateway and CDP service
 */

#include "yuka.h"
#include <unistd.h>
#include <sys/varargs.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>

#include <stropts.h>
#include <sys/conf.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/sctp.h>

#include "dlpi.h"

struct etherdot1q {
	uint16_t vlan;
	uint16_t ether_type;
};
#ifndef ETHERTYPE_DOT1Q
#define ETHERTYPE_DOT1Q (0x8100)
#endif

#include "cdp.h"

char const * const yuka_socket_path = "/var/run/cdpd_socket";
char const * const yuka_pid_path = "/var/run/cdpd.pid";
char const * const devdir = "/dev/";

/* option flags */
int gwflag = 0;
extern t_uscalar_t dlsap_addr_len;
int pflag_phys = 0;
int pflag_sap = 0;
int pflag_multi = 1;
int rflag = 0;
int mflag = 0;
int bgflag = 0;
int refresh = 0;
int verbose = 0;
int dflag = 0;
struct pollfd *pollfds = NULL;
int pollcount = 0;
yuka_session ** sessions;
int sessioncount = 0;
time_t now = 0;
t_dlsap_addr DSA_CDP;
int fd_ipc = -1;
int *fds_ipc = NULL;
int nfds_ipc = 0;
int afds_ipc = 0;

const t_data_link_addr MAC_ETHER = { {0xff,0xff,0xff,0xff,0xff,0xff} };

void ether_header_dump(const struct ether_header *p);
void ascii_out(const unsigned char *p, int n);
void dump_ether_packet(const struct ether_header *p, int l);
void dump_ip_packet(const struct ip *p, int l);
void dump_in_addr(const char *s1, const struct in_addr a, const char *s2);
char *getipp(int prot);
char *get_ether_type(int ty);
void Usage(const char *prog);
char *get_dl_mac_type(t_uscalar_t ty);
char *get_dl_service_mode(t_uscalar_t m);
void DlpiOpenSession(yuka_session *ses);
void SessionTest(yuka_session *ses);

void yuka_run_snd_session(yuka_session * ses);
int yuka_rcv_data(yuka_session *ses);
void yuka_rcv_cdp_data(yuka_session *ses, t_dlsap_addr src_addr, t_dlsap_addr dest_addr);

static char hostname[256];
// 172.16.98.254
static struct in_addr testip = { .s_addr = 0xfe6210ac };
uchar_t _yuka_test_addr[6] = { 0x00, 0xee, 0x4e, 0x78, 0x00, 0xf2 };

int
yuka_frame_alloc(yuka_packet_t **lf)
{
	uint8_t * nf;
	nf = malloc(sizeof(yuka_packet_t) + 1500);
	if(!nf) {
		return -1;
	}
	*lf = (yuka_packet_t*)nf;
	(*lf)->buf = nf + sizeof(yuka_packet_t);
	(*lf)->bufsize = 1500;
	return 0;
}

int
yuka_frame_free(yuka_packet_t *lf)
{
	free(lf);
	return 0;
}

int yuka_session_alloc(yuka_session **ses)
{
	yuka_session *session;
	session = (yuka_session*)malloc(sizeof(yuka_session));
	if(!session) return -1;
	memset(session, 0, sizeof(yuka_session));
	session->rcv.ctlbuf.buf = (int8_t*)malloc(YUKA_PRIMBUFMAX);
	session->rcv.ctlbuf.maxlen = YUKA_PRIMBUFMAX;
	session->rcv.databuf.buf = (int8_t*)malloc(YUKA_BUFMAX);
	session->rcv.databuf.maxlen = YUKA_BUFMAX;
	session->dtime = now;
	yuka_frame_alloc(&session->sndframe);
	*ses = session;
	return 0;
}

void
yuka_session_free(yuka_session *ses)
{
	close(ses->fd);
	free(ses->device);
	yuka_frame_free(ses->sndframe);
	yuka_frame_free(ses->cdpinfo);
	free((void*)ses->link);
	free(ses);
}

void
add_session_device(yuka_session * ses, const char * device)
{
	ses->device = strdup(device);
	DlpiOpenSession(ses);
	yuka_packet_t * cdpi;
	yuka_frame_alloc(&cdpi);
	yuka_cdp_init(cdpi);
	cdp_add_hostid(cdpi, hostname);
	cdp_add_ipaddress(cdpi, (in_addr_t)0);
	cdp_add_portid(cdpi, device);
	cdp_add_capabilities(cdpi, CDPCAP_HOST | CDPCAP_ROUTER | CDPCAP_SWITCH);
	cdp_add_sysname(cdpi);
	yuka_cdp_final(cdpi);
	ses->cdpinfo = cdpi;
	ses->dtime = 180;
	dl_plus_sap_to_dlsap(ses, &MAC_CDP, 0x0, DSA_CDP);
}

int
mac_equal(const void *ma, const void *mb)
{
	const uint8_t *a = (uint8_t const *)ma;
	const uint8_t *b = (uint8_t const *)mb;
	return (*((const uint32_t*)a) == *((const uint32_t*)b)) && (((const uint16_t*)a)[2] == ((const uint16_t*)b)[2]);
}

int
yuka_frame_reset(yuka_packet_t *lf)
{
	lf->insertpos = 0;
	lf->framelen = 0;
	lf->framepos = 0;
	lf->llcstart = 14;
	lf->llclen = 0;
	lf->ipstart = 0;
	return 0;
}

int
yuka_frame_reply(yuka_packet_t *lf, const uint8_t *srcmac, const yuka_packet_t *sf)
{
	if(sf->bufsize < 16 || lf->bufsize < 16) return -1;
	memcpy(lf->buf, sf->buf+6, 6);
	memcpy(lf->buf+6, srcmac, 6);
	memcpy(lf->buf+12, sf->buf+12, 2+sf->llclen);
	lf->insertpos = 14 + sf->llclen;
	lf->framelen = lf->insertpos;
	lf->framepos = 0;
	lf->llcstart = 14;
	lf->llclen = sf->llclen;
	return 0;
}

int canread(int fd) {
	if(fd < 0) return -1;
	struct pollfd uset[1];
	uset[0].events = POLLIN;
	uset[0].fd = fd;
	int i = poll(uset, 1, 0);
	if( i < 0 ) {
		perror("canread - select()");
		return -1;
	} else if( i > 0 ) {
		if(uset[0].revents & (POLLHUP | POLLNVAL | POLLERR))
			return -1;
		if(uset[0].revents & POLLIN)
			return 1;
	}
	return 0;
}

uint16_t
checksum(const void *ptr, int length)
{
	uint32_t sum = 0;
	const uint16_t *w = (const uint16_t*)ptr;
	const uint16_t *en = w + (length >> 1);

	while(w < en){
		sum += ntohs(*w++);
	}
	if(length & 1) {
		sum += *w & 0x00ff;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return htons(~sum);
}

uint32_t
checksum_b(const void *ptr, int length)
{
	uint32_t sum = 0;
	const uint16_t *w = (const uint16_t*)ptr;
	const uint16_t *en = w + (length >> 1);
	while(w < en){
		sum += ntohs(*w++);
	}
	return sum;
}
uint32_t
checksum_p(const void *ptr, int length, uint32_t ac)
{
	uint32_t sum = ac;
	const uint16_t *w = (const uint16_t*)ptr;
	const uint16_t *en = w + (length >> 1);
	while(w < en){
		sum += ntohs(*w++);
	}
	return sum;
}
uint16_t
checksum_f(const void *ptr, int length, uint32_t ac)
{
	uint32_t sum = ac;
	const uint16_t *w = (const uint16_t*)ptr;
	const uint16_t *en = w + (length >> 1);
	while(w < en){
		sum += ntohs(*w++);
	}
	if(length & 1) {
		sum += htons(*w) & 0xff00;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return htons(~sum);
}

int
add_long(yuka_packet_t * lfp, uint32_t v)
{
	if(lfp->insertpos + 4 > lfp->bufsize) {
		return -5;
	}
	*((uint32_t *)&lfp->buf[lfp->insertpos]) = htonl(v);
	lfp->insertpos += 4;
	if(lfp->insertpos > lfp->framelen) lfp->framelen = lfp->insertpos;
	return 0;
}

uint32_t
get_long(const uint8_t *rfp)
{
	uint32_t r = (uint32_t)ntohl(*(uint32_t*)(rfp));
	return r;
}

uint32_t
get_long_m(const uint8_t **rfp)
{
	uint32_t r = (uint32_t)ntohl(*(uint32_t*)(*rfp));
	(*rfp) += 4;
	return r;
}

int
add_ip(yuka_packet_t * lfp, in_addr_t v)
{
	if(lfp->insertpos + 4 > lfp->bufsize) {
		return -5;
	}
	*((in_addr_t *)&lfp->buf[lfp->insertpos]) = v;
	lfp->insertpos += 4;
	if(lfp->insertpos > lfp->framelen) lfp->framelen = lfp->insertpos;
	return 0;
}

int
add_short(yuka_packet_t * lfp, uint16_t v)
{
	if(lfp->insertpos+ 2 > lfp->bufsize) {
		return -5;
	}
	*((unsigned short *)&lfp->buf[lfp->insertpos]) = htons(v);
	lfp->insertpos += 2;
	if(lfp->insertpos > lfp->framelen) lfp->framelen = lfp->insertpos;
	return 0;
}
uint16_t
get_short(const uint8_t *rfp)
{
	uint16_t r = (uint16_t)ntohs(*(uint16_t*)(rfp));
	return r;
}
uint16_t
get_short_m(const uint8_t **rfp)
{
	uint16_t r = (uint16_t)ntohs(*(uint16_t*)(*rfp));
	(*rfp) += 2;
	return r;
}

int
add_byte(yuka_packet_t * lfp, uint8_t v)
{
	if(lfp->insertpos+ 1 > lfp->bufsize) {
		return -5;
	}
	lfp->buf[lfp->insertpos++] = v;
	if(lfp->insertpos > lfp->framelen) lfp->framelen = lfp->insertpos;
	return 0;
}

int
add_string(yuka_packet_t * lfp, const uint8_t * v, int len)
{
	if(lfp->insertpos+ len > lfp->bufsize) {
		return -5;
	}
	int i;
	for(i = 0; i < len; i++) {
		lfp->buf[lfp->insertpos++] = v[i];
	}
	if(lfp->insertpos > lfp->framelen) lfp->framelen = lfp->insertpos;
	return 0;
}

void
yuka_run_snd_session(yuka_session * ses)
{
	if(now >= ses->dtime) {
		DlpiSnd(ses, DSA_CDP, ses->cdpinfo->buf, ses->cdpinfo->framelen);
		//PutData(ses, ses->cdpinfo->buf, ses->cdpinfo->framelen);
		ses->dtime = now + 60;
	}
}

struct show_cdp_settings {
	int fd;
	int fmt;
	int index;
	char buf[1024];
};
static void show_cdp_host_V(struct cdp_host_entry * he, void * n)
{
	struct show_cdp_settings *s = (struct show_cdp_settings*)n;
	yuka_session const * lses = (yuka_session const *)he->localportid;
	const char * plat = he->platform;
	const char * portid = he->portid;
	if(s->fmt == 1) { /* formatted output requested */
		if(strncmp(plat, "cisco ", 6) == 0) {
			plat += 6;
		}
	}
	char portprefix[5];
	int portw = -13;
	char cflags[9];
	char *cfp = cflags;
	/* build the capabilities field */
	if(he->caps & CDPCAP_ROUTER) *(cfp++) = 'R';
	if(he->caps & CDPCAP_TRBRIDGE) *(cfp++) = 'T';
	if(he->caps & CDPCAP_SRBRIDGE) *(cfp++) = 'B';
	if(he->caps & CDPCAP_SWITCH) *(cfp++) = 'S';
	if(he->caps & CDPCAP_IGMP) *(cfp++) = 'I';
	if(he->caps & CDPCAP_HOST) *(cfp++) = 'H';
	if(he->caps & CDPCAP_REPEATER) *(cfp++) = 'r';
	if(he->caps & CDPCAP_PHONE) *(cfp++) = 'P';
	*cfp++ = 0;
	/* build the port ID field */
	portprefix[0] = 0;
	if(s->fmt == 1) { /* only if formatted output requested */
		if(strncmp(he->portid, "Ethernet", 8) == 0) {
			strcpy(portprefix, "Eth ");
			portid += 8;
			portw = -9;
		} else if(strncmp(he->portid, "FastEthernet", 12) == 0) {
			strcpy(portprefix, "Fas ");
			portid += 12;
			portw = -9;
		} else if(strncmp(he->portid, "GigabitEthernet", 15) == 0) {
			strcpy(portprefix, "Gig ");
			portid += 15;
			portw = -9;
		} else if(strncmp(he->portid, "TenGigabitEthernet", 18) == 0) {
			strcpy(portprefix, "Ten ");
			portid += 18;
			portw = -9;
		}
	}
	const char *fmtstr = "%s%s;%s;%d;%s;%s;%s%*s;%d\n";
	const char *objprefix = "";
	switch(s->fmt) {
	case 1:
		fmtstr = strlen(he->devid) > 18 ?
		"%s%s\n                   %-10s %3d   %-8s %-17s %s%*s %3d\n":
		"%s%-18s %-10s %3d   %-8s %-17s %s%*s %3d\n";
		break;
	case 2:
		if(s->index > 0) {
			objprefix = ",";
		}
		fmtstr = "%s{\"device\":\"%s\",\"local_port\":\"%s\","
			"\"holdtime\":%d,\"capability\":\"%s\","
			"\"platform\":\"%s\",\"remote_port\":\"%s%*s\",\"native_vlan\":%d}\n";
		break;
	case 3:
		fmtstr = "%1$s <device holdtime=\"%4$d\">\n  <name>%2$s</name>\n  <local_port>%3$s</local_port>\n"
			"  <capability>%5$s</capability>\n  <platform>%6$s</platform>\n"
			"  <remote_port>%7$s%9$*8$s</remote_port>\n  <native_vlan>%10$d</native_vlan>\n </device>\n";
		break;
	}
	int r = snprintf(s->buf, 1024, fmtstr,
		objprefix,
		he->devid,
		lses->device,
		he->holdtime,
		cflags,
		plat,
		portprefix,
		portw, portid,
		he->vlan);
	write(s->fd, s->buf, r);
	s->index++;
}
static void
yuka_show_cdp_hosts(int outfd, int fflag)
{
	if(verbose > 3) {
		printf("show cdp hosts: FD=%d, fmt=%d\n", outfd, fflag);
	}
	struct show_cdp_settings outset;
	outset.fd = outfd; /* where to output */
	outset.fmt = fflag; /* show formatted */
	outset.index = 0; /* keep track of how many */
	if(outset.fmt == 1) {
		const char *info =
"Device ID          Local Int  Hold  Capable  Platform          Port ID      VLAN\n";
/*1111-111x11xxx    e1000g11   180   RSI      WS-C1111G-24XS-E  Gig 11/11/11  111*/
		write(outset.fd, info, strlen(info));
	}
	if(outset.fmt == 2) {
		write(outset.fd, "[\n", 2);
	}
	if(outset.fmt == 3) {
		write(outset.fd, "<cdpneighbors>\n", 16);
	}
	yuka_cdp_walk(show_cdp_host_V, &outset);
	if(outset.fmt == 2) {
		write(outset.fd, "]\n", 2);
	}
	if(outset.fmt == 3) {
		write(outset.fd, "</cdpneighbors>\n", 17);
	}
}

static void
update_hold_V(struct cdp_host_entry * he, void * n)
{
	he->holdtime -= 1;
}

void
yuka_update_hold()
{
	yuka_cdp_walk(update_hold_V, NULL);
}

void
xdump(const unsigned char *p, int l)
{
	int n;

	for (n = 0; n < l; ++n) {
		if (!(n & 0xf))
			printf("    %04x: ", n);
		if (!(n & 0x7))
			putchar(' ');
		printf("%02x ", p[n]);
		if ((n & 0xf) == 0xf)
			ascii_out(p, n);
	}

	if (n & 0xf)
		ascii_out(p, n-1);
}

void
ascii_out(const unsigned char *p, int n)
{
	int i;

	for (i = (n & 0xf) + 1; i < 16; ++i) {
		if (i == 8)
			putchar(' ');
		printf("   ");
	}
	printf(" ");
	for (i = n & ~0xf; i <= n; ++i) {
		if (!(i & 0x7))
			putchar(' ');
		if (isprint(p[i]))
			putchar(p[i]);
		else
			putchar('.');
	}
	putchar('\n');
}

void
ether_header_dump(const struct ether_header *p)
{
	int t;

	nbytes_hex("    ether_dhost ",p->ether_dhost.ether_addr_octet, 6, "\n");
	nbytes_hex("    ether_shost ",p->ether_shost.ether_addr_octet, 6, "\n");
	t = ntohs(p->ether_type);
	printf("    ether_type 0x%x = %s\n", t, get_ether_type(t));
}

const char *
get_llc_sap(uchar_t c)
{
	switch(c & 0xfe) {
	default: return "???";
	case 0: return "Null";
	case 2: return "iLLC Sublayer";
	case 3: return "gLLC Sublayer";
	case 6: return "DoD IP";
	case 24: return "TI";
	case 66: return "BSTP";
	case 78: return "EIA-RS 511";
	case 94: return "ISI IP";
	case 129: return "BACnet/IP";
	case 152: return "ARP";
	case 170: return "SNAP Ext";
	case 224: return "Netware";
	case 240: return "NetBIOS";
	case 244: return "LANMan Ind";
	case 245: return "LANMan Grp";
	case 248: return "RPL";
	case 255: return "Global DSAP";
	}
}

void
dump_llc_packet(const uchar_t *p, int l)
{
	printf("  -- LLC --\n");
	if(l < 3) return;
	printf(" dest-sap: 0x%02x (%s)\n", p[0], get_llc_sap(p[0]));
	printf("  src-sap: 0x%02x (%s)\n", p[1], get_llc_sap(p[1]));
}

void
dump_arp_packet(const struct ether_arp *p, int l)
{
	if(l < sizeof(struct ether_arp)) return;
	printf("  -- ARP --\n");
	int t;
	t = ntohs(p->ea_hdr.ar_hrd);
	printf(" hw-type: %d\n", t);
	t = ntohs(p->ea_hdr.ar_op);
	printf(" op-code: %d\n", t);
	nbytes_hex("    src-ha: ", p->arp_sha, 6, "\n");
	dump_in_addr("    src-pa: ", *(struct in_addr*)p->arp_spa, "\n");
	nbytes_hex("    tgt-ha: ", p->arp_tha, 6, "\n");
	dump_in_addr("    tgt-pa: ", *(struct in_addr*)p->arp_tpa, "\n");
}

void 
dump_ether_packet(const struct ether_header *p, int l)
{
	int t;

	printf("  -- ETHER --\n");
	if (l < sizeof(struct ether_header))
		return;
	ether_header_dump(p);
	t = ntohs(p->ether_type);
	l -= sizeof(struct ether_header);
	if(t == ETHERTYPE_DOT1Q) {
		if(l < sizeof(struct etherdot1q)) return;
		const struct etherdot1q *vl = (const struct etherdot1q*)(p+1);
		p = (const struct ether_header*)(((const uint8_t*)p) + sizeof(struct etherdot1q));
		uint16_t vid = ntohs(vl->vlan);
		printf("    vlan: 0x%04x (%d)\n", vid & 0xfff, vid & 0xfff);
		printf("    priority: %d\n", vid >> 12);
		t = ntohs(vl->ether_type);
		printf("    ether_type 0x%x = %s\n", t, get_ether_type(t));
	}
	switch (t) {
	case ETHERTYPE_IP:
		dump_ip_packet((struct ip *)(p + 1), l);
		break;
	case ETHERTYPE_ARP:
		dump_arp_packet((struct ether_arp*)(p + 1), l);
		break;
	default:
		if(t < 1501) {
			dump_llc_packet((uchar_t*)(p+1), l);
			//printf("  -- DATA --\n");
			//xdump((uchar_t*)(p+1), l);
		}
		break;
	}
}

void
dump_ip_packet(const struct ip *p, int l)
{
	printf("  -- IP --\n");
	if (l < sizeof(struct ip))
		return;
	dump_in_addr("    ip_src ", p->ip_src, "\n");
	dump_in_addr("    ip_dst ", p->ip_dst, "\n");
	printf("    ip_p %d = %s\n", p->ip_p, getipp( p->ip_p));
}

void
dump_in_addr(const char *s1, const struct in_addr a, const char *s2)
{
	if (s1)
		printf("%s", s1);
	printf("%d.%d.%d.%d", a._S_un._S_un_b.s_b1, a._S_un._S_un_b.s_b2,
		a._S_un._S_un_b.s_b3, a._S_un._S_un_b.s_b4);
	if (s2)
		printf("%s", s2);
}

void 
nbytes_hex(const char *s1, const uchar_t *b, int n, const char *s2)
{
	int k;

	if (s1)
		printf("%s", s1);
	printf("%02x", b[0]);
	for (k = 1; k < n; ++k)
		printf(":%02x", b[k]);
	if (s2)
		printf("%s", s2);
}

void
Warn(char *str, ...)
{
        va_list ap;
	int e;

	e = errno;

        va_start(ap, str);
        vfprintf(stderr, str, ap);
	va_end(ap);
        fprintf(stderr, " - platform warning\n" );

	if (e)
		fprintf(stderr, "system error %d: %s\n", e, strerror(e));
}

void
Error(char *str, ...)
{
        va_list ap;
	int e;

	e = errno;

        va_start(ap, str);
        vfprintf(stderr, str, ap);
	va_end(ap);
        fprintf(stderr, " - platform error, exiting\n" );

	if (e)
		fprintf(stderr, "system error %d: %s\n", e, strerror(e));

        exit(1);
}

char *
getipp(int prot)
{
	switch (prot) {
	case IPPROTO_HOPOPTS:	return "IPPROTO_HOPOPTS";
	case IPPROTO_ICMP:	return "IPPROTO_ICMP";
	case IPPROTO_IGMP:	return "IPPROTO_IGMP";
	case IPPROTO_GGP:	return "IPPROTO_GGP";
	case IPPROTO_ENCAP:	return "IPPROTO_ENCAP";
	case IPPROTO_TCP:	return "IPPROTO_TCP";
	case IPPROTO_EGP:	return "IPPROTO_EGP";
	case IPPROTO_PUP:	return "IPPROTO_PUP";
	case IPPROTO_UDP:	return "IPPROTO_UDP";
	case IPPROTO_IDP:	return "IPPROTO_IDP";
	case IPPROTO_IPV6:	return "IPPROTO_IPV6";
	case IPPROTO_ROUTING:	return "IPPROTO_ROUTING";
	case IPPROTO_FRAGMENT:	return "IPPROTO_FRAGMENT";
	case IPPROTO_RSVP:	return "IPPROTO_RSVP";
	case IPPROTO_ESP:	return "IPPROTO_ESP";
	case IPPROTO_AH:	return "IPPROTO_AH";
	case 0x58:		return "IPPROTO_EIGRP";
	case IPPROTO_OSPF:	return "IPPROTO_OSPF";
	case IPPROTO_ICMPV6:	return "IPPROTO_ICMPV6";
	case IPPROTO_NONE:	return "IPPROTO_NONE";
	case IPPROTO_DSTOPTS:	return "IPPROTO_DSTOPTS";
	case IPPROTO_HELLO:	return "IPPROTO_HELLO";
	case IPPROTO_ND:	return "IPPROTO_ND";
	case IPPROTO_EON:	return "IPPROTO_EON";
	case 97:		return "IPPROTO_ETHERNET";
	case IPPROTO_PIM:	return "IPPROTO_PIM";
	case IPPROTO_RAW:	return "IPPROTO_RAW";
	default: return "???";
	}
}

void
dump_tcp_headers(const uchar_t *buf, int l)
{
	char tcpflags[9] = "--------";
	uint8_t tf;
	printf("  -- TCP --\n");
	if(l < sizeof(struct tcphdr)) return;
	struct tcphdr *p = (struct tcphdr*)buf;
	printf("    src-port: %d\n", ntohs(p->th_sport));
	printf("    dest-port: %d\n", ntohs(p->th_dport));
	printf("    seq: %d\n", ntohl(p->th_seq));
	printf("    ack: %d\n", ntohl(p->th_ack));
	tf = p->th_flags;
	if(tf & TH_CWR) tcpflags[0] = 'C';
	if(tf & TH_ECE) tcpflags[1] = 'E';
	if(tf & TH_URG) tcpflags[2] = 'U';
	if(tf & TH_ACK) tcpflags[3] = 'A';
	if(tf & TH_PUSH) tcpflags[4] = 'P';
	if(tf & TH_RST) tcpflags[5] = 'R';
	if(tf & TH_SYN) tcpflags[6] = 'S';
	if(tf & TH_FIN) tcpflags[7] = 'F';
	printf("    flags: %s\n", tcpflags);
}
void dump_udp_headers(yuka_packet_t *fr)
{
	printf("  -- UDP --\n");
	struct ip *iph = (struct ip*)(fr->buf + fr->ipstart);
	struct udphdr *p = (struct udphdr*)(fr->buf + fr->framepos);
	int l = fr->framelen - fr->framepos;
	printf("    src-port: %d\n", ntohs(p->uh_sport));
	printf("    dst-port: %d\n", ntohs(p->uh_dport));
	printf("    length: %d (%d)\n", ntohs(p->uh_ulen), l);
	uint32_t ac = checksum_b(&iph->ip_src, 8);
	ac += iph->ip_p; ac += ntohs(p->uh_ulen);
	uint16_t chk = checksum_f(p, l, ac);
	printf("    checksum: 0x%04x <%04x %s>\n", p->uh_sum, chk, chk ? "BAD":"OK");
}

void
yuka_parse_udp(yuka_session *ses, yuka_packet_t *fr)
{
	if(dflag) dump_udp_headers(fr);
	struct ip *iph = (struct ip*)(fr->buf + fr->ipstart);
	struct udphdr *p = (struct udphdr*)(fr->buf + fr->framepos);
	int l = fr->framelen - fr->framepos;
	uint32_t ac = checksum_b(&iph->ip_src, 8);
	ac += iph->ip_p; ac += ntohs(p->uh_ulen);
	//uint16_t chk = checksum_f(p, l, ac);
	//if(chk) return;
	if(ntohs(p->uh_ulen) > l) return;
	int dl = ntohs(p->uh_ulen) - sizeof(struct udphdr);
	if(dflag) printf("    packet OK\n");
	if(dflag) xdump((uint8_t*)(p+1), dl);
}

void
yuka_parse_icmp(yuka_session *ses, yuka_packet_t *fr)
{
	struct icmp *p = (struct icmp*)(fr->buf + fr->framepos);
	if(fr->framelen - fr->framepos < sizeof(struct icmp)) return;
	fr->framepos += sizeof(struct icmp);
	uint16_t chk = checksum(p, fr->framelen - fr->framepos);
	printf("  -- ICMP --\n"
		"    type: %d:%d\n"
		"    sum: 0x%04x <%s>\n"
		" DATA:\n",
		p->icmp_type, p->icmp_code,
		p->icmp_cksum, chk?"BAD":"OK");
	xdump((uint8_t*)(p+1), fr->framelen - fr->framepos);
}

void
yuka_parse_ip_packet(yuka_session *ses, yuka_packet_t *fr)
{
	struct ip *np = (struct ip*)(fr->buf + fr->framepos);
	if(fr->framelen - fr->framepos < sizeof(struct ip)) return;
	if(!gwflag || np->ip_dst.s_addr != testip.s_addr) {
		//return;
	}
	fr->ipstart = fr->framepos;
	if(dflag) dump_ip_packet(np, fr->framelen - fr->framepos);
	uint16_t chk = checksum(np, np->ip_hl << 2);
	if(dflag && verbose > 3) printf("    checksum: 0x%04x <%s>\n", np->ip_sum, chk ? "BAD" : "OK");
	fr->framepos += np->ip_hl << 2;
	switch(np->ip_p) {
	case IPPROTO_ICMP:
		yuka_parse_icmp(ses, fr);
		break;
	case IPPROTO_TCP:
		if(dflag) dump_tcp_headers((const uchar_t*)(fr->buf+fr->framepos), fr->framelen - fr->framepos);
		break;
	case IPPROTO_UDP:
		yuka_parse_udp(ses, fr);
		break;
	default: break;
	}
}

void
yuka_parse_arp_packet(yuka_session *ses, yuka_packet_t *fr)
{
	if(fr->framelen - fr->framepos < sizeof(struct ether_arp)) return;
	int t;
	struct ether_arp *ap = (struct ether_arp*)(fr->buf + fr->framepos);
	t = ntohs(ap->ea_hdr.ar_hrd);
	if(t != 1) return; // only ethernet
	t = ntohs(ap->ea_hdr.ar_op);
	/*
	if(verbose > 2) {
		printf("ARP%d - ", t);
		nbytes_hex("SM=", ap->arp_sha, 6, " ");
		dump_in_addr("sIP=", *(struct in_addr*)ap->arp_spa, " -- ");
		nbytes_hex("TM=", ap->arp_tha, 6, " ");
		dump_in_addr("tIP=", *(struct in_addr*)ap->arp_tpa, "\n");
	}
	*/
	if(gwflag && ((struct in_addr*)(ap->arp_tpa))->s_addr == testip.s_addr) {
		printf(" RECV TEST IP ARP\n");
		yuka_frame_reply(ses->sndframe, _yuka_test_addr, fr);
		add_short(ses->sndframe, 1);
		add_short(ses->sndframe, ETHERTYPE_IP);
		add_byte(ses->sndframe, 6);
		add_byte(ses->sndframe, 4);
		add_short(ses->sndframe, 2);
		add_string(ses->sndframe, _yuka_test_addr, 6);
		add_ip(ses->sndframe, testip.s_addr);
		add_string(ses->sndframe, ap->arp_sha, 6);
		add_ip(ses->sndframe, *((in_addr_t*)(ap->arp_spa)));
		xdump(ses->sndframe->buf, ses->sndframe->framelen);
		dump_ether_packet((struct ether_header*)ses->sndframe->buf, ses->sndframe->framelen);
		PutData(ses, ses->sndframe->buf, ses->sndframe->framelen);
	}
}

void
yuka_parse_frame(yuka_session *ses, yuka_packet_t *fr)
{
	int t;
	const struct ether_header *p = (const struct ether_header*)(fr->buf + fr->framepos);
	if (fr->framelen < sizeof(struct ether_header)) {
		if(verbose > 2) {
			printf("frame length is too short: %d\n", fr->framelen);
		}
		return;
	}
	if(mac_equal(&p->ether_shost, ses->link->dev_addr)) {
		return;
	}
	fr->framepos += sizeof(struct ether_header);
	t = ntohs(p->ether_type);
	if(t == ETHERTYPE_DOT1Q) {
		if(fr->framelen - fr->framepos < sizeof(struct etherdot1q)) {
			if(verbose > 2) {
				printf("VLAN frame length is too short: %d\n", fr->framelen);
			}
		}
		const struct etherdot1q *vl = (const struct etherdot1q*)(p+1);
		fr->framepos += (fr->llclen += sizeof(struct etherdot1q));
		t = ntohs(vl->ether_type);
	}
	/*
	if( (p->ether_dhost.ether_addr_octet[0] & 1)
		|| (mac_equal(p->ether_dhost.ether_addr_octet, _yuka_test_addr)) ) {
	} else {
		return;
	}
	*/
	if(dflag > 0) {
		dump_ether_packet(p, fr->framelen);
	}
	switch (t) {
	case ETHERTYPE_IP:
		yuka_parse_ip_packet(ses, fr);
		break;
	case ETHERTYPE_ARP:
		yuka_parse_arp_packet(ses, fr);
		break;
	default:
		if(t < 1501) {
			if(mac_equal(p->ether_dhost.ether_addr_octet, &MAC_CDP)) {
				struct cdp_host_entry cdphost;
				if(!yuka_cdp_parse(fr->buf + fr->framepos, fr->framelen - fr->framepos, &cdphost)) {
					cdphost.localportid = ses;
					yuka_cdp_refresh(&cdphost);
				}
			}
		}
		break;
	}
}

int
yuka_rcv_data(yuka_session *ses)
{
	yuka_packet_t eth;
	t_dlsap_addr src_addr, dest_addr;
	eth.buf = (uint8_t *)ses->rcv.databuf.buf;
	eth.bufsize = ses->rcv.databuf.maxlen;
	yuka_frame_reset(&eth);

	DlpiRcv(ses, src_addr, dest_addr);
	eth.framelen = ses->rcv.databuf.len;
	yuka_parse_frame(ses, &eth);

	ses->frames_in++;
	if(dflag > 0) {
		printf("received:");
		nbytes_hex(" src ", src_addr, dlsap_addr_len, NULL);
		nbytes_hex(" dest ", dest_addr, dlsap_addr_len, NULL);
		printf(" data-len %d\n", eth.framelen);
		xdump(eth.buf, eth.framelen);
	}
	return (dest_addr[0] & 1);
}

void
yuka_rcv_cdp_data(yuka_session *ses, t_dlsap_addr src_addr, t_dlsap_addr dest_addr)
{
	struct cdp_host_entry cdphost;

	DlpiRcv(ses, src_addr, dest_addr);

	uint64_t dest_r = MAC_ETHER.qa[0] & *((uint64_t*)dest_addr);
	if(0 == (dest_r ^ MAC_CDP.qa[0])) {
		if(dflag > 0) {
			printf("received:");
			nbytes_hex(" src ", src_addr, dlsap_addr_len, NULL);
			nbytes_hex(" dest ", dest_addr, dlsap_addr_len, NULL);
			//if(p_unitdata_ind->dl_group_address) printf(" group_address");
			printf(" data-len %d\n", ses->rcv.databuf.len);
			xdump((uint8_t *)ses->rcv.databuf.buf, ses->rcv.databuf.len);
		}
		if(!yuka_cdp_parse((uint8_t *)ses->rcv.databuf.buf, ses->rcv.databuf.len, &cdphost)) {
			cdphost.localportid = ses;
			yuka_cdp_refresh(&cdphost);
		}
	}
}

void
connect_ipc()
{
	int ufd;
	struct sockaddr_un addr;
	ufd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(ufd < 0) perror("ipc: socket()");
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, yuka_socket_path);
	if(connect(ufd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un))) {
		if(errno == ENOENT || errno == ECONNREFUSED) {
			fprintf(stderr, "service not running or started incorrectly\n");
			exit(1);
		} else {
			perror("ipc: connect()");
			exit(1);
		}
	}
	fd_ipc = ufd;
}

int
yuka_handle_ipc(int ipfd)
{
	int r;
	char buf[1024];
	if(verbose > 3)
		printf("handle_ipc for FD: %d\n", ipfd);
	r = recv(ipfd, buf, 1024, 0);
	if(r < 1) return 1;
	if(verbose > 3) {
		printf("ipc-recv:\n");
		xdump((uint8_t *)buf, r);
	}
	switch(buf[0]) {
	case 1: /* show */
		if(r < 2) return -1;
		switch(buf[1]) {
		case 1: /* cdp */
			if(r < 3) {
				yuka_show_cdp_hosts(ipfd, 0);
			} else {
				yuka_show_cdp_hosts(ipfd, buf[2]);
			}
			break;
		default:
			write(ipfd, "Command Error\n", 14);
			break;
		}
		break;
	default:
		break;
	}
	return 1;
}

void
init_ipc()
{
	int ufd;
	struct sockaddr_un addr;
	ufd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(ufd < 0) perror("ipc: socket()");
	if(unlink(yuka_socket_path) < 0 && errno != ENOENT) perror("ipc: unlink()");
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, yuka_socket_path);
	if(bind(ufd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)))
		perror("ipc: bind");
	if(fchmod(ufd, 0444)) {
		perror("ipc: fchmod");
	}
	if(listen(ufd, 10)) {
		perror("ipc: listen");
	}
	fd_ipc = ufd;
}

void
deinit_ipc()
{
	close(fd_ipc);
	if(unlink(yuka_socket_path) < 0) perror("deinit-ipc: unlink()");
}

struct yuka_command {
	const char *name;
	uint8_t code;
	struct yuka_command *sub;
};

static struct yuka_command yuka_show_commands[] = {
	{"cdp", 1, 0},
	{0, 0, 0}
};
static struct yuka_command yuka_commands[] = {
	{"show", 1, yuka_show_commands},
	{0, 0, 0}
};

int
yuka_search_commands(const char * cmd, int cmdlen, struct yuka_command const *cmdlist)
{
	int index = 0;
	int find = -1;
	for(;cmdlist->name; index++, cmdlist++) {
		int scl = strlen(cmdlist->name);
		if(cmdlen > scl) continue;
		if(!strncmp(cmd, cmdlist->name, cmdlen)) {
			if(find != -1) return -2;
			find = index;
		}
	}
	return find;
}

void
Usage(const char *prog)
{
   fprintf(stderr, 
"usage:\n"
"# %1$s -r [options] [<device> ...]  -- run cdp on all interfaces or specific interfaces\n"
"$ %1$s -l                           -- list available interfaces\n"
"$ %1$s [options] [<command> ...]    -- query the service\n"
" Options:\n"
"   -R             same as '-r' but run in the background.\n"
"   -fm -fj -fx    change output format. (generic, JSON, XML)\n"
"   -p <level>     enable a promiscuous level. (repeatable)\n"
"                  level = p[hys] s[ap] m[ulti]\n"
"   -v             verbose output. (repeatable for more verbosity)\n"
"   -d             dump frames.\n"
, prog);

   exit(1);
}

static const char *my_opt;
static int my_optind = 1;
static int my_optofs = 0;
static const char ** my_list = NULL;
static int my_listsize = 0;

int
yuka_getopt(int argc, const char * const *argv, const char *args)
{
trytryagain:
	if(my_optind >= argc) return -1;
	my_opt = argv[my_optind];
	int c = argv[my_optind][0];
	if(c == '-') {
		c = argv[my_optind][1 + my_optofs];
		if(!c) {
			my_optofs = 0;
			my_optind++;
			goto trytryagain;
		}
		my_opt = argv[my_optind] + 2 + my_optofs;
		for(int x = 0; args[x]; x++) {
			if(c == args[x]) {
				if(args[x + 1] == ':') {
					my_optind++;
					my_optofs = 0;
					if(*my_opt == 0) {
						if(my_optind < argc) {
							my_opt = argv[my_optind++];
						} else {
							return '?';
						}
					}
				} else {
					my_optofs++;
				}
				return c;
			}
			if(args[x + 1] == ':') {
				x++;
			}
		}
		return '?';
	} else {
		my_opt = argv[my_optind++];
		my_listsize++;
		if(!my_list) {
			my_list = (const char **)malloc(sizeof(char*) * my_listsize);
		} else {
			my_list = (const char **)realloc(my_list, sizeof(char*) * my_listsize);
		}
		my_list[my_listsize - 1] = my_opt;
		return 1;
	}
}

void
yuka_int_handler()
{
	fprintf(stderr, "interrupt\n");
	rflag = 0;
}

void
yuka_pipe_handler()
{
	if(verbose > 1) fprintf(stderr, "PIPE error\n");
}

void
yuka_user_handler()
{
	fprintf(stderr, "got SIGUSR1\n");
	yuka_show_cdp_hosts(1, 1);
}

void
yuka_hup_handler()
{
	if(!bgflag) rflag = 0;
	else refresh = 1;
}

void
yuka_register_handlers()
{
	struct sigaction nact;
	nact.sa_handler = yuka_int_handler;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGINT);
	nact.sa_flags = 0;
	sigaction(SIGINT, &nact, NULL);

	nact.sa_handler = yuka_pipe_handler;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGPIPE);
	nact.sa_flags = 0;
	sigaction(SIGPIPE, &nact, NULL);

	nact.sa_handler = yuka_hup_handler;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGHUP);
	nact.sa_flags = 0;
	sigaction(SIGHUP, &nact, NULL);

	nact.sa_handler = yuka_user_handler;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGUSR1);
	nact.sa_flags = 0;
	sigaction(SIGUSR1, &nact, NULL);
}

void
enter_service()
{
	verbose = 0;
	close(0);
	close(1);
	close(2);
	if(fork()) {
		exit(0);
	}
	setsid();
	chdir("/");
	pid_t pid;
	pid = getpid();
	unlink(yuka_pid_path);
	umask(0);
	int pidf = open(yuka_pid_path, O_WRONLY | O_CREAT, 0644);
	if(pidf > -1) {
		char buf[32];
		int n = snprintf(buf, 32, "%d", pid);
		if(n > 32) n = 32;
		write(pidf, buf, n);
		close(pidf);
	}
}

int
main(int argc, const char **argv)
{
	int c;
	int fflag = 1;

	now = time(NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	while ((c = yuka_getopt(argc, argv, ":a:p:i:f:Rrdmvhl")) != EOF) {
		switch(c) {
		case 1:
			break;
		case 'p':
			if (!strcmp(my_opt,"p") || !strcmp(my_opt,"phys") || !strcmp(my_opt,"promiscuous"))
				pflag_phys = 1;
			else if (!strcmp(my_opt,"s") || !strcmp(my_opt,"sap"))
				pflag_sap = 1;
			else if (!strcmp(my_opt,"m") || !strcmp(my_opt,"multi"))
				pflag_multi = 1;
			else
				Error("-p option: unknown level %s", my_opt);
			break;
		case 'f':
			if(!strcmp(my_opt,"m")) fflag = 0;
			else if(!strcmp(my_opt,"j")) fflag = 2;
			else if(!strcmp(my_opt,"x")) fflag = 3;
			break;
		case 'i':
			if(!inet_aton(my_opt, &testip)) {
				Error("-i option: bad address %s", my_opt);
			}
			gwflag = 1;
			pflag_sap = 1;
			pflag_multi = 1;
			pflag_phys = 1;
			break;
		case 'R':
			bgflag = 1;
			/* fall through */
		case 'r':
			rflag = 1;
			pflag_multi = 1;
			break;
		case 'm':
			mflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'l':
			yuka_list_links();
			return 0;
		case '?':
		case 'h':
		default:
			Usage(argv[0]);
		}
	}

	gethostname(hostname, 256);
	for(int x = 0; x < my_listsize; x++) {
		if(verbose > 2)
			printf("option: %s\n", my_list[x]);
		sessioncount++;
	}

	if(!rflag) {
		if(!my_listsize) return 0;
		connect_ipc();
		uint8_t * cs = (uint8_t*)malloc(1024);
		uint8_t * cse = cs + 3;
		int textcmds = 0;
		cs[2] =fflag & 0xff;
		struct yuka_command * currentlist = yuka_commands;
		for(int x = 0; x < my_listsize; x++) {
			if(verbose > 2)
				printf("option: %s\n", my_list[x]);
			if(currentlist) {
				int ccc = yuka_search_commands(my_list[x], strlen(my_list[x]), currentlist);
				if(ccc < 0) {
					fprintf(stderr, "Unknown command or sub command: %s\n", my_list[x]);
					return 1;
				}
				if(verbose > 2)
					printf("cmd-code: %d\n", currentlist[ccc].code);
				if(x < 2) {
					cs[x] = currentlist[ccc].code;
				} else {
					*cse = currentlist[ccc].code;
					cse++;
				}
				currentlist = currentlist[ccc].sub;
			} else {
				int ccl = strlen(my_list[x]);
				memcpy(cse, my_list[x], ccl);
				cse += ccl;
				*cse++ = 0;
				textcmds++;
			}
		}
		if(textcmds) *cse++ = 0;
		send(fd_ipc, cs, cse - cs, 0);
		int rstatus;
		while((rstatus = canread(fd_ipc)) >= 0) {
			if(rstatus > 0) {
				rstatus = read(fd_ipc, cs, 1024);
				if(rstatus > 0) write(1, cs, rstatus);
				else {
					close(fd_ipc);
					fd_ipc = -1;
				}
			}
		}
		free(cs);
		if(fd_ipc > -1) close(fd_ipc);
		return 0;
	}
	if(verbose > 1) {
		printf("verbosity: %d\n", verbose);
	}
	if(verbose > 2)
		printf("Sessions: %d\n", sessioncount);
	if(sessioncount > 0) {
		int skip = 0;

		sessions = (yuka_session**)malloc(sizeof(void*) * sessioncount);
		for(int x = 0; x < my_listsize; x++) {
			if(strncmp(my_list[x], devdir, 5) == 0) {
				skip = 5;
			} else {
				skip = 0;
			}
			yuka_session_alloc(&sessions[x]);
			add_session_device(sessions[x], my_list[x] + skip);
		}
	} else {
		struct yuka_string_list *lst = NULL, *lsti;
		yuka_get_links(&lst);
		if(!lst) {
			fprintf(stderr, "No links to listen on - exiting\n");
		}
		lsti = lst;
		while(lsti) {
			sessioncount++;
			lsti = lsti->next;
		}
		sessions = (yuka_session**)malloc(sizeof(void*) * sessioncount);
		lsti = lst;
		for(int x = 0; lsti; x++) {
			yuka_session_alloc(&sessions[x]);
			add_session_device(sessions[x], lsti->str);
			lsti = lsti->next;
		}
		yuka_free_links(lst);
	}

	init_ipc();
	yuka_register_handlers();
	if(verbose > 2)
		printf("Yuka has started running.\n");
	if(bgflag) enter_service();
	int lasttime = now = time(NULL);
	while (rflag) {
		int pindex;
		now = time(NULL);
		if(lasttime != now) {
			yuka_update_hold();
			lasttime = now;
		}
		int pextra = sessioncount + 1 + nfds_ipc;
		if(pollcount != pextra) {
			pollcount = pextra;
			if(pollfds) {
				free(pollfds);
				pollfds = NULL;
			}
			pollfds = (struct pollfd*)malloc(sizeof(struct pollfd) * pollcount);
			for(pindex = 0; pindex < sessioncount; pindex++) {
				pollfds[pindex].fd = sessions[pindex]->fd;
				pollfds[pindex].events = POLLIN | POLLOUT;
			}
			pollfds[pindex].fd = fd_ipc;
			pollfds[pindex].events = POLLIN;
			pindex++;
			for(int x = 0; x < nfds_ipc; x++) {
				pollfds[pindex].fd = fds_ipc[x];
				pollfds[pindex].events = POLLIN | POLLOUT;
				pindex++;
			}
		}
		int n = 1;
		int rep = 1000;
		int frames_in_total = 0;
		int foflag = 0;
		while(n && rep) {
			n = poll(pollfds, pollcount, 1);
			rep--;
			if(n < 0) {
				perror("poll");
			} else if(n) {
				for(pindex = 0; pindex < sessioncount; pindex++) {
					if(pollfds[pindex].revents & POLLIN) {
						foflag |= yuka_rcv_data(sessions[pindex]);
					}
					if(pollfds[pindex].revents & POLLOUT) {
						yuka_run_snd_session(sessions[pindex]);
					}
					frames_in_total += sessions[pindex]->frames_in;
				}
				if(pollfds[pindex].revents & POLLIN) {
					struct sockaddr_un addr;
					socklen_t addrlen = sizeof(struct sockaddr_un);
					int accfd = -1;
					accfd = accept4(fd_ipc,
							(struct sockaddr*)&addr,
							&addrlen,
							SOCK_NDELAY | SOCK_NONBLOCK);
					if(nfds_ipc + 1 >= afds_ipc) {
						while(nfds_ipc + 1 < afds_ipc) afds_ipc += 16;
						int *np = (int*)malloc(sizeof(int) * afds_ipc);
						if(fds_ipc) {
							for(int x = 0; x < nfds_ipc; x++) {
								np[x] = fds_ipc[x];
							}
							free(fds_ipc);
						}
						fds_ipc = np;
					}
					fds_ipc[nfds_ipc] = accfd;
					nfds_ipc++;
				}
				pindex++;
				for(int x = 0; x < nfds_ipc; x++) {
					int cfd = pollfds[pindex].fd;
					int cev = pollfds[pindex].revents;
					pindex++;
					if(cev & POLLIN) {
						if(yuka_handle_ipc(cfd)) {
							cev |= POLLHUP; /* close us */
						}
					}
					if(cev & (POLLHUP | POLLERR)) {
						if(verbose > 3)
							printf("closing ipc for FD: %d\n", cfd);
						close(cfd);
						nfds_ipc--;
						for(int y = x; y < nfds_ipc; y++) {
							fds_ipc[y] = fds_ipc[y+1];
						}
						x--;
					}
				}
			}
		}
		if(foflag && verbose > 1) {
			printf("\r% 10d recv.", frames_in_total);
		}
	}
	for(int x = 0; x < sessioncount; x++) {
		yuka_session_free(sessions[x]);
	}
	free(sessions);
	deinit_ipc();
}

