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
 * DLPI interface module
 */

#include "yuka.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>

#include <sys/conf.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/socket.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
//#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "dlpi.h"
#include "cdp.h"

extern char const * const devdir;

/* option flags */
extern int bflag;
t_uscalar_t dlsap_addr_len;
extern int pflag_phys;
extern int pflag_sap;
extern int pflag_multi;
extern int rflag;
extern int scflag;
extern int verbose;
extern int dflag;

static int rawmode = 1;

void DlpiSet(t_uscalar_t prim_type, void *prim, int len);
void PutDlpiMsg(yuka_session *ses, void *prim, int prim_len, void *data, int data_len);
void GetDlpiMsg(yuka_session *ses);
void DlpiChk(t_uscalar_t prim_type, void *prim, const char *ctx);
char *get_dl_mac_type(t_uscalar_t ty);
char *get_dl_service_mode(t_uscalar_t m);
void DlpiChkOk(yuka_session *ses, t_uscalar_t correct_primitive);
const char * get_dl_error(t_uscalar_t m);
void DlpiPromiscon(yuka_session *ses, t_uscalar_t promisc_type, char *s);
void DlpiOpenSession(yuka_session *ses);

void
DlpiOpenSession(yuka_session * ses)
{
	t_uscalar_t style;
	dl_info_req_t dl_info_req;
	dl_info_ack_t *p_info_ack;
	t_uscalar_t service_mode;
	dl_phys_addr_req_t dl_phys_addr_req;
	dl_attach_req_t dl_attach_req;
	dl_phys_addr_ack_t *p_phys_addr_ack;
	dl_bind_req_t dl_bind_req;
	dl_bind_ack_t *p_bind_ack;
	t_data_link_addr dl_addr;
	t_uscalar_t sap2;

	if(ses->device[0] == '/') {
		ses->fd = open(ses->device, O_RDWR);
	} else {
		char *dfn;
		dfn = (char*)malloc(strlen(devdir) + strlen(ses->device) + 1);
		strcpy(dfn, devdir);
		strcat(dfn, ses->device);
		if(verbose > 0) printf("openning device %s ...", dfn);
		ses->fd = open(dfn, O_RDWR);
		free(dfn);
	}
	if (ses->fd < 0) {
		Error("cannot open device %s", ses->device);
	}
	struct yuka_dlpi_info *link = (struct yuka_dlpi_info*)malloc(sizeof(struct yuka_dlpi_info));
	if(!link)
		Error("DlpiOpenSession - out of memory");
	ses->link = link;

	/*** DL_INFO_REQ **************************************************/
	DlpiSet(DL_INFO_REQ, &dl_info_req, sizeof(dl_info_req));
	PutDlpiMsg(ses, &dl_info_req, sizeof(dl_info_req), NULL, 0);
	p_info_ack = (dl_info_ack_t *)ses->rcv.ctlbuf.buf;
	while(GetDlpiMsg(ses), p_info_ack->dl_primitive == DL_UNITDATA_IND);
	DlpiChk(DL_INFO_ACK, p_info_ack, "DL_INFO_REQ");
	if(verbose > 3) {
		printf(
			"dl_max_sdu %lu, dl_min_sdu %lu\n"
			"dl_addr_length %lu\n"
			"dl_addr_offset %lu\n"
			"dl_mac_type %lu = %s\n"
			"dl_sap_length %ld\n"
			"dl_service_mode %lu = %s\n"
			"dl_provider_style 0x%lx = %s\n"
			"dl_version %lu\n",
			p_info_ack->dl_max_sdu, p_info_ack->dl_min_sdu,
			p_info_ack->dl_addr_length,
			p_info_ack->dl_addr_offset,
			p_info_ack->dl_mac_type, get_dl_mac_type(p_info_ack->dl_mac_type),
			p_info_ack->dl_sap_length,
			p_info_ack->dl_service_mode, get_dl_service_mode(p_info_ack->dl_service_mode),
			p_info_ack->dl_provider_style,
			(
			p_info_ack->dl_provider_style == DL_STYLE1 ? "DL_STYLE1":
			p_info_ack->dl_provider_style == DL_STYLE2 ? "DL_STYLE2":
			"???"
			),
			p_info_ack->dl_version
		);
	}
	style = p_info_ack->dl_provider_style;
	service_mode = p_info_ack->dl_service_mode;

	/*** DL_ATTACH_REQ ************************************************/
	if (style == DL_STYLE2) {
		if(verbose > 1)
			printf(" ppa=%d", 0);
		DlpiSet(DL_ATTACH_REQ, &dl_attach_req, sizeof(dl_attach_req_t));
		dl_attach_req.dl_ppa = 0;
		PutDlpiMsg(ses, &dl_attach_req, sizeof(dl_attach_req_t), NULL, 0);
		DlpiChkOk(ses, DL_ATTACH_REQ);
	}

	/*** DL_PHYS_ADDR_REQ *********************************************/
	DlpiSet(DL_PHYS_ADDR_REQ, &dl_phys_addr_req, sizeof(dl_info_req));
	dl_phys_addr_req.dl_addr_type = DL_CURR_PHYS_ADDR;
	PutDlpiMsg(ses, &dl_phys_addr_req, sizeof(dl_phys_addr_req), NULL, 0);
	p_phys_addr_ack = (dl_phys_addr_ack_t *)ses->rcv.ctlbuf.buf;
	while(GetDlpiMsg(ses), p_phys_addr_ack->dl_primitive == DL_UNITDATA_IND);
	DlpiChk(DL_PHYS_ADDR_ACK, p_phys_addr_ack, "DL_PHYS_ADDR_REQ");
	if(verbose > 0)
		nbytes_hex(" phys=", 
			(uchar_t *)p_phys_addr_ack + p_phys_addr_ack->dl_addr_offset, 
			p_phys_addr_ack->dl_addr_length, "");
	link->data_link_addr_len = p_phys_addr_ack->dl_addr_length;
	/*
	if (sflag && send_addr_len != data_link_addr_len)
		Error("-s option: invalid address length %d, should be %d",
			send_addr_len, data_link_addr_len);
			*/

	/*** DL_BIND_REQ **************************************************/
	DlpiSet(DL_BIND_REQ, &dl_bind_req, sizeof(dl_bind_req));
	dl_bind_req.dl_sap = 0x0000; /* bind to sap */
	dl_bind_req.dl_max_conind = 0;
	dl_bind_req.dl_service_mode = service_mode;
	dl_bind_req.dl_conn_mgmt = 0;
	dl_bind_req.dl_xidtest_flg = 0;
	if(verbose > 1)
		printf(" sap=%#0x", dl_bind_req.dl_sap);
	PutDlpiMsg(ses, &dl_bind_req, sizeof(dl_bind_req), NULL, 0);
	p_bind_ack = (dl_bind_ack_t *)ses->rcv.ctlbuf.buf;
	while(GetDlpiMsg(ses), p_bind_ack->dl_primitive == DL_UNITDATA_IND);
	DlpiChk(DL_BIND_ACK, p_bind_ack, "DL_BIND_REQ");
	if(verbose > 1)
		nbytes_hex(" bindaddr=", 
			(uchar_t *)p_bind_ack + p_bind_ack->dl_addr_offset, 
			p_bind_ack->dl_addr_length, "");

	if(verbose > 0)
		printf("\n");
	/*** second DL_INFO_REQ, after bind, get dlsap addr info **********/
	DlpiSet(DL_INFO_REQ, &dl_info_req, sizeof(dl_info_req));
	PutDlpiMsg(ses, &dl_info_req, sizeof(dl_info_req), NULL, 0);
	p_info_ack = (dl_info_ack_t *)ses->rcv.ctlbuf.buf;
	while(GetDlpiMsg(ses), p_info_ack->dl_primitive == DL_UNITDATA_IND);
	DlpiChk(DL_INFO_ACK, p_info_ack, "DL_INFO_ACK");
	if (p_info_ack->dl_addr_offset <= 0)
		Error("no dlsap address after bind");
	if(verbose > 1)	printf("dl_sap_length %ld\n", p_info_ack->dl_sap_length);
	if (p_info_ack->dl_sap_length == 0)
		Error("dl_sap_length = 0 after bind");
	link->sap_length = p_info_ack->dl_sap_length;
	if(p_info_ack->dl_sap_length < 0) p_info_ack->dl_sap_length = -p_info_ack->dl_sap_length;
	dlsap_to_dl_plus_sap(ses,
		(uchar_t *)p_info_ack + p_info_ack->dl_addr_offset,
		&dl_addr,
		&sap2);
	if (link->data_link_addr_len + p_info_ack->dl_sap_length != p_info_ack->dl_addr_length)
		Error("data_link_addr_len (%d) + sap_length (%d) "
			"!= dl_addr_length (%d)", link->data_link_addr_len,
			p_info_ack->dl_sap_length, p_info_ack->dl_addr_length);
	dlsap_addr_len = p_info_ack->dl_addr_length;
	memcpy(link->dev_addr, (uchar_t *)p_info_ack + p_info_ack->dl_addr_offset, 
		dlsap_addr_len);
	if(verbose > 1) {
		nbytes_hex("full dlsap address ", link->dev_addr,
			p_info_ack->dl_addr_length, " = \n");
		nbytes_hex("   dll addr ", dl_addr.a, link->data_link_addr_len, ", ");
		printf("sap 0x%x\n", sap2);
	}
	if(rawmode) {
		ioctl(ses->fd, DLIOCRAW);
	}
	/*** DL_PROMISCON_REQ *********************************************/
	if (pflag_phys) /* "physical" level - this echos back sent traffic */
		DlpiPromiscon(ses, DL_PROMISC_PHYS, "DL_PROMISC_PHYS");
	if (pflag_multi) /* multicast level - all multicast frames */
		DlpiPromiscon(ses, DL_PROMISC_MULTI, "DL_PROMISC_MULTI");
	if (pflag_sap) /* SAP level - traffic on all SAPs, aka *everything!* */
		DlpiPromiscon(ses, DL_PROMISC_SAP, "DL_PROMISC_SAP");
	p_info_ack->dl_primitive = 0;
	ses->rcv.ctlbuf.len = 0;
}

char *
get_ether_type(int ty)
{
	switch (ty) {
	case 0:			return "ALL";
	case ETHERTYPE_PUP:	return "ETHERTYPE_PUP";
	case ETHERTYPE_IP:	return "ETHERTYPE_IP";
	case ETHERTYPE_ARP:	return "ETHERTYPE_ARP";
	case ETHERTYPE_REVARP:	return "ETHERTYPE_REVARP";
	case ETHERTYPE_IPV6:	return "ETHERTYPE_IPV6";
	case 0x8100:		return "ETHERTYPE_DOT1Q";
	default:	return "???";
	}
}

void
DlpiSet(t_uscalar_t prim_type, void *prim, int len)
{
	memset(prim, 0, len);
	((union DL_primitives *)prim)->dl_primitive = prim_type;
}

void
PutData(yuka_session *ses, const void *data, int data_len)
{
	int flags, e;
	struct strbuf databuf;

	if(!data) return;
	databuf.buf = (char *)data;
	databuf.len = data_len;

	flags = 0;

	e = putmsg(ses->fd, NULL, (data ? &databuf : NULL), flags);
	if (e)
		Error("putmsg data");
}

void
PutDlpiMsg(yuka_session * ses, void *prim, int prim_len, void *data, int data_len)
{
	int flags, e;
	struct strbuf ctlbuf, databuf;

	ctlbuf.buf = (char *)prim;
	ctlbuf.len = prim_len;

	databuf.buf = (char *)data;
	databuf.len = data_len;

	flags = 0;

	e = putmsg(ses->fd, &ctlbuf, (data ? &databuf : NULL), flags);
	if (e)
		Error("putmsg prim 0x%x", 
			((union DL_primitives *)prim)->dl_primitive);
}

/* returns data length read
 */
void
GetDlpiMsg(yuka_session * ses)
{
	int flags, e;
	flags = 0;

	struct strbuf dat;
	dat.buf = ses->rcv.databuf.buf;
	dat.maxlen = ses->rcv.databuf.maxlen;
	ses->rcv.ctlbuf.len = 0;
	ses->rcv.databuf.len = 0;
	e = MOREDATA;
	while(dat.maxlen && e & MOREDATA) {
		e = getmsg(ses->fd, &ses->rcv.ctlbuf, &dat, &flags);
		if(dat.len < 0) break;
		ses->rcv.databuf.len += dat.len;
		dat.buf += dat.len;
		dat.maxlen -= dat.len;
	}
	if (e & (MORECTL | MOREDATA))
		Warn("getmsg e=%s%s, ctlbuf.len %d, data_len %d", 
			(e & MORECTL ? "MORECTL " : ""),
			(e & MOREDATA ? "MOREDATA": ""),
			ses->rcv.ctlbuf.len, ses->rcv.databuf.len);
	else if (e)
		Error("getmsg: %s", strerror(errno));
}

const char *
get_dl_prim(t_uscalar_t m)
{
	switch(m) {
	case DL_INFO_REQ: return "DL_INFO_REQ";
	case DL_ATTACH_REQ: return "DL_ATTACH_REQ";
	case DL_DETACH_REQ: return "DL_DETACH_REQ";
	case DL_BIND_REQ: return "DL_BIND_REQ";
	case DL_UNBIND_REQ: return "DL_UNBIND_REQ";
	case DL_SUBS_BIND_REQ: return "DL_SUBS_BIND_REQ";
	case DL_SUBS_UNBIND_REQ: return "DL_SUBS_UNBIND_REQ";
	case DL_ENABMULTI_REQ: return "DL_ENABMULTI_REQ";
	case DL_DISABMULTI_REQ: return "DL_DISABMULTI_REQ";
	case DL_PROMISCON_REQ: return "DL_PROMISCON_REQ";
	case DL_PROMISCOFF_REQ: return "DL_PROMISCOFF_REQ";
	case DL_UNITDATA_REQ: return "DL_UNITDATA_REQ";
	case DL_UDQOS_REQ: return "DL_UDQOS_REQ";
	case DL_PHYS_ADDR_REQ: return "DL_PHYS_ADDR_REQ";
	case DL_PHYS_ADDR_ACK: return "DL_PHYS_ADDR_ACK";
	/*
	case : return "";
	*/
	case DL_INFO_ACK: return "DL_INFO_ACK";
	case DL_BIND_ACK: return "DL_BIND_ACK";
	case DL_SUBS_BIND_ACK: return "DL_SUBS_BIND_ACK";
	case DL_UNITDATA_IND: return "DL_UNITDATA_IND";
	case DL_UDERROR_IND: return "DL_UDERROR_IND";
	case DL_OK_ACK: return "DL_OK_ACK";
	case DL_ERROR_ACK: return "DL_ERROR_ACK";
	case DL_DATA_ACK_IND: return "DL_DATA_ACK_IND";
	default: return "<OTHER>";
	}
}

void
DlpiChk(t_uscalar_t prim_type, void *prim, const char *ctx)
{
	union DL_primitives *p = prim;

	if (p->dl_primitive == prim_type) {
		if(verbose > 3) printf("%s DlpiChk: got expected %s (%#x)\n", ctx, get_dl_prim(prim_type), prim_type);
		return;
	}

	if(!ctx) ctx = "";
	if (p->dl_primitive == DL_ERROR_ACK)
		Error("%s DlpiChk: expected dl_primitive 0x%0x,\n"
			"         got DL_ERROR_ACK"
			" dl_errno 0x%x (%s), dl_unix_errno %d", ctx,
			prim_type, p->error_ack.dl_errno, get_dl_error(p->error_ack.dl_errno), 
			p->error_ack.dl_unix_errno);

	if (p->dl_primitive == DL_OK_ACK)
		Error("%s DlpiChk: expected dl_primitive %s (%#x), got DL_OK_ACK for %s (%#x)", ctx,
			get_dl_prim(prim_type), prim_type,
			get_dl_prim(p->ok_ack.dl_correct_primitive), p->ok_ack.dl_correct_primitive
			);
	Error("%s DlpiChk: expected dl_primitive %s (%#0x), got %s (%#0x)", ctx,
		get_dl_prim(prim_type), prim_type, get_dl_prim(p->dl_primitive), p->dl_primitive);
}

char *
get_dl_mac_type(t_uscalar_t ty)
{
	switch (ty) {
	    case DL_CSMACD:	return "DL_CSMACD";
	    case DL_TPB:	return "DL_TPB";
	    case DL_TPR:	return "DL_TPR";
	    case DL_METRO: 	return "DL_METRO";
	    case DL_ETHER: 	return "DL_ETHER";
	    case DL_HDLC: 	return "DL_HDLC";
	    case DL_CHAR: 	return "DL_CHAR";
	    case DL_CTCA: 	return "DL_CTCA";
	    case DL_FDDI: 	return "DL_FDDI";
	    case DL_FC: 	return "DL_FC";
	    case DL_ATM: 	return "DL_ATM";
	    case DL_IPATM: 	return "DL_IPATM";
	    case DL_X25: 	return "DL_X25";
	    case DL_ISDN: 	return "DL_ISDN";
	    case DL_HIPPI: 	return "DL_HIPPI";
	    case DL_100VG: 	return "DL_100VG";
	    case DL_100VGTPR: 	return "DL_100VGTPR";
	    case DL_ETH_CSMA: 	return "DL_ETH_CSMA";
	    case DL_100BT: 	return "DL_100BT";
	    case DL_FRAME: 	return "DL_FRAME";
	    case DL_MPFRAME: 	return "DL_MPFRAME";
	    case DL_ASYNC: 	return "DL_ASYNC";
	    case DL_IPX25: 	return "DL_IPX25";
	    case DL_LOOP: 	return "DL_LOOP";
	    case DL_OTHER: 	return "DL_OTHER";
	    default: return "???";
	}
}

const char *
get_dl_error(t_uscalar_t m)
{
	switch(m) {
		case DL_SYSERR: return "DL_SYSERR";
		case DL_ACCESS: return "DL_ACCESS";
		case DL_TOOMANY: return "DL_TOOMANY";
		case DL_BADADDR: return "DL_BADADDR";
		case DL_BADPPA: return "DL_BADPPA";
		case DL_OUTSTATE: return "DL_OUTSTATE";
		case DL_NOTSUPPORTED: return "DL_NOTSUPPORTED";
		case DL_UNSUPPORTED: return "DL_UNSUPPORTED";
		default: return "???";
	}
}

char *
get_dl_service_mode(t_uscalar_t m)
{
	switch (m) {
	    case DL_CODLS:	return "DL_CODLS";
	    case DL_CLDLS:	return "DL_CLDLS";
	    case DL_ACLDLS:	return "DL_ACLDLS";
	    default: return "???";
	}
}

void
DlpiChkOk(yuka_session *ses, t_uscalar_t correct_primitive)
{
	dl_ok_ack_t *ok = (dl_ok_ack_t *)ses->rcv.ctlbuf.buf;
	union DL_primitives *p = (union DL_primitives *)ses->rcv.ctlbuf.buf;

	do {
		GetDlpiMsg(ses);
		if(ok->dl_primitive == DL_UNITDATA_IND) printf("#DAT");
	} while(ses->rcv.ctlbuf.len < 0 || ok->dl_primitive == DL_UNITDATA_IND);
	if (ok->dl_primitive == DL_OK_ACK && ok->dl_correct_primitive == correct_primitive) {
		if(verbose > 3) printf("DlpiChkOk: got DL_OK_ACK for %s (%#x)\n",
			get_dl_prim(p->ok_ack.dl_correct_primitive),
			p->ok_ack.dl_correct_primitive);
		return;
	}

	if (ok->dl_primitive == DL_ERROR_ACK)
		Error(  "DlpiChkOk: expected dl_primitive DL_OK_ACK,\n"
			"           got DL_ERROR_ACK"
			" dl_errno 0x%x, dl_unix_errno %d",
			p->error_ack.dl_errno, 
			p->error_ack.dl_unix_errno);

	if (ok->dl_primitive != DL_OK_ACK)
		Error("DlpiChkOk: expected DL_OK_ACK got %s (0x%x)", 
			get_dl_prim(ok->dl_primitive), ok->dl_primitive);
	if (ok->dl_correct_primitive != correct_primitive)
		Error("DlpiChkOk: expected correct_primitive %s (0x%x) got %s (0x%x)",
			get_dl_prim(correct_primitive), correct_primitive,
			get_dl_prim(ok->dl_correct_primitive), ok->dl_correct_primitive);
}

void 
dlsap_to_dl_plus_sap(yuka_session const *ses, uint8_t const *dlsap, t_data_link_addr *dl_addr, 
	t_uscalar_t *psap)
{
	struct yuka_dlpi_info const * link = ses->link;

	if (link->sap_length >= 0) {
		memcpy(dl_addr, dlsap + link->sap_length, link->data_link_addr_len);
		*psap = bytes_to_uscalar(dlsap, link->sap_length);
	} else {
		memcpy(dl_addr, dlsap, link->data_link_addr_len);
		*psap = bytes_to_uscalar(dlsap + link->data_link_addr_len, -link->sap_length);
	}
}

void 
dl_plus_sap_to_dlsap(yuka_session const *ses, const t_data_link_addr *dl_addr, 
		t_uscalar_t sap, uint8_t *dlsap)
{
	struct yuka_dlpi_info const *link = ses->link;

	if (link->sap_length >= 0) {
		memcpy(dlsap + link->sap_length, dl_addr, link->data_link_addr_len);
		uscalar_to_bytes(dlsap, link->sap_length, sap);
	} else {
		memcpy(dlsap, dl_addr, link->data_link_addr_len);
		uscalar_to_bytes(dlsap + link->data_link_addr_len, -link->sap_length, sap);
	}
}

t_uscalar_t
bytes_to_uscalar(uchar_t const *p, int l)
{
	int inc, n;
	t_uscalar_t res;

	if (l > sizeof(t_uscalar_t))
		Error("bytes_to_uscalar: l = %d", l);

#ifdef __i386
	inc = -1;
	p += l - 1;
#else
	inc = 1;
#endif

	res = 0;
	for (n = 0; n < l; ++n, p += inc)
		res = (res << 8) | *p;
	
	return res;
}

void
uscalar_to_bytes(uchar_t *p, int l, t_uscalar_t u)
{
	int inc, n;

	if (l > sizeof(t_uscalar_t)) Error("uscalar_to_bytes: l = %d", l);

#ifdef __i386
	inc = 1;
#else
	inc = -1;
	p += l - 1;
#endif

	for (n = 0; n < l; ++n, p += inc) {
		*p = u & 0xff;
		u >>= 8;
	}
}

void DlpiSnd(yuka_session *ses, t_dlsap_addr dlsap_addr, uchar_t *buf, int len)
{
	dl_unitdata_req_t *p_unitdata_req;

	p_unitdata_req = (dl_unitdata_req_t *)ses->rcv.ctlbuf.buf;
	DlpiSet(DL_UNITDATA_REQ, p_unitdata_req, sizeof(dl_unitdata_req_t));
	p_unitdata_req->dl_dest_addr_length = dlsap_addr_len;
	p_unitdata_req->dl_dest_addr_offset = sizeof(dl_unitdata_req_t);
	p_unitdata_req->dl_priority.dl_min = 0;
	p_unitdata_req->dl_priority.dl_max = 0;
	memcpy((uchar_t *)p_unitdata_req + p_unitdata_req->dl_dest_addr_offset,
		       	dlsap_addr, dlsap_addr_len);
	PutDlpiMsg(ses, p_unitdata_req, sizeof(dl_unitdata_req_t) + dlsap_addr_len, buf, len);
}

void DlpiRcv(yuka_session *ses, t_dlsap_addr src_addr, t_dlsap_addr dest_addr)
{
	dl_unitdata_ind_t *p_unitdata_ind;
	uchar_t *p;

	p = (uchar_t *)ses->rcv.ctlbuf.buf;
	p_unitdata_ind = (dl_unitdata_ind_t *)p;
	GetDlpiMsg(ses);
	if(rawmode) {
		if(ses->rcv.databuf.len <= 14) return;
		memcpy(dest_addr, ses->rcv.databuf.buf, 6); // ethernet framing
		((uint16_t*)src_addr)[3] = 0;
		memcpy(src_addr, ses->rcv.databuf.buf + 6, 6);
		((uint16_t*)dest_addr)[3] = ((uint16_t*)ses->rcv.databuf.buf)[6];
		if(ses->rcv.ctlbuf.len > 0 && p_unitdata_ind->dl_primitive != DL_UNITDATA_IND) return;
	}
	if(ses->rcv.ctlbuf.len <= 0) return;
	DlpiChk(DL_UNITDATA_IND, p_unitdata_ind, ses->device);

	if (p_unitdata_ind->dl_src_addr_offset > 0) {
		if (p_unitdata_ind->dl_src_addr_length != dlsap_addr_len)
			Error("DlpiRcv src_addr_length %d", p_unitdata_ind->dl_src_addr_length);
		memcpy(src_addr, p + p_unitdata_ind->dl_src_addr_offset, dlsap_addr_len);
	} else memset(src_addr, 0, dlsap_addr_len);

	if (p_unitdata_ind->dl_dest_addr_offset > 0) {
		if (p_unitdata_ind->dl_dest_addr_length != dlsap_addr_len)
			Error("DlpiRcv dest_addr_length %d", p_unitdata_ind->dl_dest_addr_length);
		memcpy(dest_addr, p + p_unitdata_ind->dl_dest_addr_offset, dlsap_addr_len);
	} else memset(dest_addr, 0, dlsap_addr_len);
}

void 
DlpiPromiscon(yuka_session *ses, t_uscalar_t promisc_type, char *s)
{
	dl_promiscon_req_t promiscon_req;

	if(verbose > 1)
	printf("setting promiscuous mode %s\n", s);
	DlpiSet(DL_PROMISCON_REQ, &promiscon_req, sizeof(dl_promiscon_req_t));
	promiscon_req.dl_level = promisc_type;
	PutDlpiMsg(ses, &promiscon_req, sizeof(dl_promiscon_req_t), NULL, 0);
	DlpiChkOk(ses, DL_PROMISCON_REQ);
}
