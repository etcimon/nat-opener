module natop.internals.rtnetlink;

version (linux):

extern (C):
@system:
nothrow:

import core.sys.posix.sys.types;
import natop.internals.netlink;
/*
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
*/

/* rtnetlink families. Values up to 127 are reserved for real address
 * families, values above 128 may be used arbitrarily.
 */
enum RTNL_FAMILY_IPMR		= 128;
enum RTNL_FAMILY_IP6MR		= 129;
enum RTNL_FAMILY_MAX		= 129;

/****
 *		Routing/neighbour discovery messages.
 ****/

/* Types of messages */

enum {
	RTM_BASE	= 16,
	RTM_NEWLINK	= 16,
	RTM_DELLINK,
	RTM_GETLINK,
	RTM_SETLINK,
	
	RTM_NEWADDR	= 20,
	RTM_DELADDR,
	RTM_GETADDR,
	
	RTM_NEWROUTE	= 24,
	RTM_DELROUTE,
	RTM_GETROUTE,
	
	RTM_NEWNEIGH	= 28,
	RTM_DELNEIGH,
	RTM_GETNEIGH,
	
	RTM_NEWRULE	= 32,
	RTM_DELRULE,
	RTM_GETRULE,
	
	RTM_NEWQDISC	= 36,
	RTM_DELQDISC,
	RTM_GETQDISC,
	
	RTM_NEWTCLASS	= 40,
	RTM_DELTCLASS,
	RTM_GETTCLASS,
	
	RTM_NEWTFILTER	= 44,
	RTM_DELTFILTER,
	RTM_GETTFILTER,
	
	RTM_NEWACTION	= 48,
	RTM_DELACTION,
	RTM_GETACTION,
	
	RTM_NEWPREFIX	= 52,
	
	RTM_GETMULTICAST = 58,
	
	RTM_GETANYCAST	= 62,
	
	RTM_NEWNEIGHTBL	= 64,
	RTM_GETNEIGHTBL	= 66,
	RTM_SETNEIGHTBL,
	
	RTM_NEWNDUSEROPT = 68,
	
	RTM_NEWADDRLABEL = 72,
	RTM_DELADDRLABEL,
	RTM_GETADDRLABEL,
	
	RTM_GETDCB = 78,
	RTM_SETDCB,
	
	RTM_NEWNETCONF = 80,
	RTM_GETNETCONF = 82,
	
	RTM_NEWMDB = 84,
	RTM_DELMDB = 85,
	RTM_GETMDB = 86,
	
	RTM_NEWNSID = 88,
	RTM_DELNSID = 89,
	RTM_GETNSID = 90,
	
	__RTM_MAX,
	RTM_MAX =	(((__RTM_MAX + 3) & ~3) - 1)
}

enum RTM_NR_MSGTYPES = (RTM_MAX + 1 - RTM_BASE);
enum RTM_NR_FAMILIES = (RTM_NR_MSGTYPES >> 2);
int RTM_FAM(int cmd)	{
	return (((cmd) - RTM_BASE) >> 2);
}

/* 
   Generic structure for encapsulation of optional route information.
   It is reminiscent of sockaddr, but with sa_family replaced
   with attribute type.
 */

struct rtattr {
	ushort	rta_len;
	ushort	rta_type;
}

/* Macros to handle rtattributes */

enum RTA_ALIGNTO	= 4u;
uint RTA_ALIGN(uint len) {
	return ( (len+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) );
}
bool RTA_OK(rta, uint len) {
	return (len >= cast(uint)rtattr.sizeof && 
		rta.rta_len >= rtattr.sizeof && 
		rta.rta_len <= len);
}

rtattr* RTA_NEXT(rtattr* rta, ref uint attrlen) {
	attrlen -= RTA_ALIGN(rta.rta_len);
	return cast(rtattr*)((cast(char*)rta) + RTA_ALIGN(rta.rta_len));
}

uint RTA_LENGTH(uint len) {
	return (RTA_ALIGN(rtattr.sizeof) + len);
}

uint RTA_SPACE(uint len) {
	return RTA_ALIGN(RTA_LENGTH(len));
}

void* RTA_DATA(rtattr* rta) {
	return (cast(void*)((cast(char*)rta) + RTA_LENGTH(0)));
}   

uint RTA_PAYLOAD(rtattr* rta) {
	return cast(uint)(rta.rta_len - RTA_LENGTH(0));
} 

/******************************************************************************
 *		Definitions used in routing table administration.
 ****/

struct rtmsg {
	ubyte		rtm_family;
	ubyte		rtm_dst_len;
	ubyte		rtm_src_len;
	ubyte		rtm_tos;
	
	ubyte		rtm_table;	/* Routing table id */
	ubyte		rtm_protocol;	/* Routing protocol; see below	*/
	ubyte		rtm_scope;	/* See below */	
	ubyte		rtm_type;	/* See below	*/
	
	uint		rtm_flags;
}

/* rtm_type */

enum {
	RTN_UNSPEC,
	RTN_UNICAST,		/* Gateway or direct route	*/
	RTN_LOCAL,		/* Accept locally		*/
	RTN_BROADCAST,		/* Accept locally as broadcast,
				   send as broadcast */
	RTN_ANYCAST,		/* Accept locally as broadcast,
				   but send as unicast */
	RTN_MULTICAST,		/* Multicast route		*/
	RTN_BLACKHOLE,		/* Drop				*/
	RTN_UNREACHABLE,	/* Destination is unreachable   */
	RTN_PROHIBIT,		/* Administratively prohibited	*/
	RTN_THROW,		/* Not in this table		*/
	RTN_NAT,		/* Translate this address	*/
	RTN_XRESOLVE,		/* Use external resolver	*/
	__RTN_MAX
}

enum RTN_MAX = (__RTN_MAX - 1);


/* rtm_protocol */

enum {
	RTPROT_UNSPEC	= 0,
	RTPROT_REDIRECT	= 1,	/* Route installed by ICMP redirects;
					   not used by current IPv4 */
	RTPROT_KERNEL	= 2,	/* Route installed by kernel		*/
	RTPROT_BOOT	= 3,	/* Route installed during boot		*/
	RTPROT_STATIC	= 4,	/* Route installed by administrator	*/
	
	/* Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
	   they are just passed from user and back as is.
	   It will be used by hypothetical multiple routing daemons.
	   Note that protocol values should be standardized in order to
	   avoid conflicts.
	 */
	
	RTPROT_GATED	= 8,	/* Apparently, GateD */
	RTPROT_RA	= 9,	/* RDISC/ND router advertisements */
	RTPROT_MRT	= 10,	/* Merit MRT */
	RTPROT_ZEBRA	= 11,	/* Zebra */
	RTPROT_BIRD	= 12,	/* BIRD */
	RTPROT_DNROUTED	= 13,	/* DECnet routing daemon */
	RTPROT_XORP	= 14,	/* XORP */
	RTPROT_NTK	= 15,	/* Netsukuku */
	RTPROT_DHCP	= 16,      /* DHCP client */
	RTPROT_MROUTED	= 17,      /* Multicast daemon */
	RTPROT_BABEL	= 42      /* Babel daemon */
}
/* rtm_scope

   Really it is not scope, but sort of distance to the destination.
   NOWHERE are reserved for not existing destinations, HOST is our
   local addresses, LINK are destinations, located on directly attached
   link and UNIVERSE is everywhere in the Universe.

   Intermediate values are also possible f.e. interior routes
   could be assigned a value between UNIVERSE and LINK.
*/

enum rt_scope_t {
	RT_SCOPE_UNIVERSE = 0,
	/* User defined values  */
	RT_SCOPE_SITE = 200,
	RT_SCOPE_LINK = 253,
	RT_SCOPE_HOST = 254,
	RT_SCOPE_NOWHERE = 255
}

/* rtm_flags */

enum {
	RTM_F_NOTIFY		= 0x100,	/* Notify user of route change	*/
	RTM_F_CLONED		= 0x200,	/* This route is cloned		*/
	RTM_F_EQUALIZE		= 0x400,	/* Multipath equalizer: NI	*/
	RTM_F_PREFIX		= 0x800,	/* Prefix addresses		*/
	RTM_F_LOOKUP_TABLE	= 0x1000	/* set rtm_table to FIB lookup result */
}
/* Reserved table identifiers */

alias rt_class_t = ubyte;
enum : rt_class_t {
	RT_TABLE_UNSPEC = 0,
	/* User defined values */
	RT_TABLE_COMPAT = 252,
	RT_TABLE_DEFAULT = 253,
	RT_TABLE_MAIN = 254,
	RT_TABLE_LOCAL = 255

}

enum RT_TABLE_MAX = 0xFFFFFFFF;

/* Routing message attributes */

enum rtattr_type_t {
	RTA_UNSPEC,
	RTA_DST,
	RTA_SRC,
	RTA_IIF,
	RTA_OIF,
	RTA_GATEWAY,
	RTA_PRIORITY,
	RTA_PREFSRC,
	RTA_METRICS,
	RTA_MULTIPATH,
	RTA_PROTOINFO, /* no longer used */
	RTA_FLOW,
	RTA_CACHEINFO,
	RTA_SESSION, /* no longer used */
	RTA_MP_ALGO, /* no longer used */
	RTA_TABLE,
	RTA_MARK,
	RTA_MFC_STATS,
	RTA_VIA,
	RTA_NEWDST,
	RTA_PREF,
	RTA_ENCAP_TYPE,
	RTA_ENCAP,
	RTA_EXPIRES,
	__RTA_MAX
}

enum RTA_MAX = (__RTA_MAX - 1);

rtattr* RTM_RTA(rtmsg* r) {
	return (cast(rtattr*)((cast(char*)r) + NLMSG_ALIGN(rtmsg.sizeof)));
}  
uint RTM_PAYLOAD(uint n) {
	return NLMSG_PAYLOAD(n, rtmsg.sizeof);
}
/* RTM_MULTIPATH --- array of struct rtnexthop.
 *
 * "struct rtnexthop" describes all necessary nexthop information,
 * i.e. parameters of path to a destination via this nexthop.
 *
 * At the moment it is impossible to set different prefsrc, mtu, window
 * and rtt for different paths from multipath.
 */

struct rtnexthop {
	ushort		rtnh_len;
	ubyte		rtnh_flags;
	ubyte		rtnh_hops;
	int			rtnh_ifindex;
}

/* rtnh_flags */

enum {
	RTNH_F_DEAD		= 1,	/* Nexthop is dead (used by multipath)	*/
	RTNH_F_PERVASIVE	= 2,	/* Do recursive gateway lookup	*/
	RTNH_F_ONLINK		= 4,	/* Gateway is forced on link	*/
	RTNH_F_OFFLOAD		= 8,	/* offloaded route */
	RTNH_F_LINKDOWN		= 16,	/* carrier-down on nexthop */
	
	RTNH_COMPARE_MASK	= (RTNH_F_DEAD | RTNH_F_LINKDOWN)
}
/* Macros to handle hexthops */

enum RTNH_ALIGNTO	= 4;
uint RTNH_ALIGN(uint len) {
	return cast(uint)( (len+RTNH_ALIGNTO-1) & ~(RTNH_ALIGNTO-1) );
}
bool RTNH_OK(rtnexthop* rtnh, uint len) {
	return (rtnh.rtnh_len >= rtnexthop.sizeof && (cast(uint)rtnh.rtnh_len) <= len);
}
rtnexthop* RTNH_NEXT(rtnexthop* rtnh){
	return (cast(rtnexthop*)((cast(char*)rtnh) + RTNH_ALIGN(rtnh.rtnh_len)));
}
uint RTNH_LENGTH(uint len) {
	return (RTNH_ALIGN(rtnexthop.sizeof) + len);
}
uint RTNH_SPACE(uint len) {
	return RTNH_ALIGN(RTNH_LENGTH(len));
}
rtattr* RTNH_DATA(rtnexthop* rtnh) {
	return (cast(rtattr*)((cast(char*)rtnh) + RTNH_LENGTH(0)));
}

/* RTA_VIA */
struct rtvia {
	__kernel_sa_family_t	rtvia_family;
	ubyte			rtvia_addr[0];
}

/* RTM_CACHEINFO */

struct rta_cacheinfo {
	uint	rta_clntref;
	uint	rta_lastuse;
	int	rta_expires;
	uint	rta_error;
	uint	rta_used;
	
	enum RTNETLINK_HAVE_PEERINFO = 1;
	uint	rta_id;
	uint	rta_ts;
	uint	rta_tsage;
}

/* RTM_METRICS --- array of struct rtattr with types of RTAX_* */

enum {
	RTAX_UNSPEC,
	RTAX_LOCK,
	RTAX_MTU,
	RTAX_WINDOW,
	RTAX_RTT,
	RTAX_RTTVAR,
	RTAX_SSTHRESH,
	RTAX_CWND,
	RTAX_ADVMSS,
	RTAX_REORDERING,
	RTAX_HOPLIMIT,
	RTAX_INITCWND,
	RTAX_FEATURES,
	RTAX_RTO_MIN,
	RTAX_INITRWND,
	RTAX_QUICKACK,
	RTAX_CC_ALGO,
	__RTAX_MAX
}

enum RTAX_MAX = (__RTAX_MAX - 1);

enum {
	RTAX_FEATURE_ECN	= (1 << 0),
	RTAX_FEATURE_SACK	= (1 << 1),
	RTAX_FEATURE_TIMESTAMP	= (1 << 2),
	RTAX_FEATURE_ALLFRAG	= (1 << 3),
	RTAX_FEATURE_MASK = (RTAX_FEATURE_ECN | RTAX_FEATURE_SACK | RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG)
}

struct rta_session {
	ubyte	proto;
	ubyte	pad1;
	ushort	pad2;
	
	union {
		struct ports {
			ushort	sport;
			ushort	dport;
		} ports ports;
		
		struct icmpt {
			ubyte	type;
			ubyte	code;
			ushort	ident;
		} icmpt icmpt;
		
		uint		spi;
	} u;
}

struct rta_mfc_stats {
	ulong	mfcs_packets;
	ulong	mfcs_bytes;
	ulong	mfcs_wrong_if;
}

/****
 *		General form of address family dependent message.
 ****/

struct rtgenmsg {
	ubyte		rtgen_family;
}

/*****************************************************************
 *		Link layer specific messages.
 ****/

/* struct ifinfomsg
 * passes link level specific information, not dependent
 * on network protocol.
 */

struct ifinfomsg {
	ubyte	ifi_family;
	ubyte	__ifi_pad;
	ushort	ifi_type;		/* ARPHRD_* */
	int		ifi_index;		/* Link index	*/
	uint	ifi_flags;		/* IFF_* flags	*/
	uint	ifi_change;		/* IFF_* change mask */
}

/********************************************************************
 *		prefix information 
 ****/

struct prefixmsg {
	ubyte	prefix_family;
	ubyte	prefix_pad1;
	ushort	prefix_pad2;
	int		prefix_ifindex;
	ubyte	prefix_type;
	ubyte	prefix_len;
	ubyte	prefix_flags;
	ubyte	prefix_pad3;
}

enum 
{
	PREFIX_UNSPEC,
	PREFIX_ADDRESS,
	PREFIX_CACHEINFO,
	__PREFIX_MAX
}

enum PREFIX_MAX	= (__PREFIX_MAX - 1);

struct prefix_cacheinfo {
	uint	preferred_time;
	uint	valid_time;
}


/*****************************************************************
 *		Traffic control messages.
 ****/

struct tcmsg {
	ubyte	tcm_family;
	ubyte	tcm__pad1;
	ushort	tcm__pad2;
	int		tcm_ifindex;
	uint		tcm_handle;
	uint		tcm_parent;
	uint		tcm_info;
}

enum {
	TCA_UNSPEC,
	TCA_KIND,
	TCA_OPTIONS,
	TCA_STATS,
	TCA_XSTATS,
	TCA_RATE,
	TCA_FCNT,
	TCA_STATS2,
	TCA_STAB,
	__TCA_MAX
}

enum TCA_MAX = (__TCA_MAX - 1);

rtattr* TCA_RTA(tcmsg* r) {
	return (cast(rtattr*)((cast(char*)r) + NLMSG_ALIGN(tcmsg.sizeof)));
}

uint TCA_PAYLOAD(uint n) {
	return NLMSG_PAYLOAD(n, tcmsg.sizeof);
}

/********************************************************************
 *		Neighbor Discovery userland options
 ****/

struct nduseroptmsg {
	ubyte	nduseropt_family;
	ubyte	nduseropt_pad1;
	ushort	nduseropt_opts_len;	/* Total length of options */
	int		nduseropt_ifindex;
	ubyte		nduseropt_icmp_type;
	ubyte		nduseropt_icmp_code;
	ushort	nduseropt_pad2;
	uint	nduseropt_pad3;
	/* Followed by one or more ND options */
}

enum {
	NDUSEROPT_UNSPEC,
	NDUSEROPT_SRCADDR,
	__NDUSEROPT_MAX
}

enum NDUSEROPT_MAX	= (__NDUSEROPT_MAX - 1);

/* RTnetlink multicast groups - backwards compatibility for userspace */
enum {
	RTMGRP_LINK		= 1,
	RTMGRP_NOTIFY		= 2,
	RTMGRP_NEIGH		= 4,
	RTMGRP_TC		= 8
}

enum {
	RTMGRP_IPV4_IFADDR	= 0x10,
	RTMGRP_IPV4_MROUTE	= 0x20,
	RTMGRP_IPV4_ROUTE	= 0x40,
	RTMGRP_IPV4_RULE	= 0x80
}

enum {
	RTMGRP_IPV6_IFADDR	= 0x100,
	RTMGRP_IPV6_MROUTE	= 0x200,
	RTMGRP_IPV6_ROUTE	= 0x400,
	RTMGRP_IPV6_IFINFO	= 0x800
}

enum {
	RTMGRP_DECnet_IFADDR    = 0x1000,
	RTMGRP_DECnet_ROUTE     = 0x4000
}
enum RTMGRP_IPV6_PREFIX	= 0x20000;


/* RTnetlink multicast groups */
enum rtnetlink_groups {
	RTNLGRP_NONE,
	RTNLGRP_LINK,
	RTNLGRP_NOTIFY,
	RTNLGRP_NEIGH,
	RTNLGRP_TC,
	RTNLGRP_IPV4_IFADDR,
	RTNLGRP_IPV4_MROUTE,
	RTNLGRP_IPV4_ROUTE,
	RTNLGRP_IPV4_RULE,
	RTNLGRP_IPV6_IFADDR,
	RTNLGRP_IPV6_MROUTE,
	RTNLGRP_IPV6_ROUTE,
	RTNLGRP_IPV6_IFINFO,
	RTNLGRP_DECnet_IFADDR,
	RTNLGRP_NOP2,
	RTNLGRP_DECnet_ROUTE,
	RTNLGRP_DECnet_RULE,
	RTNLGRP_NOP4,
	RTNLGRP_IPV6_PREFIX,
	RTNLGRP_IPV6_RULE,
	RTNLGRP_ND_USEROPT,
	RTNLGRP_PHONET_IFADDR,
	RTNLGRP_PHONET_ROUTE,
	RTNLGRP_DCB,
	RTNLGRP_IPV4_NETCONF,
	RTNLGRP_IPV6_NETCONF,
	RTNLGRP_MDB,
	RTNLGRP_MPLS_ROUTE,
	RTNLGRP_NSID,
	__RTNLGRP_MAX
}

enum RTNLGRP_MAX	= (__RTNLGRP_MAX - 1);

/* TC action piece */
struct tcamsg {
	ubyte	tca_family;
	ubyte	tca__pad1;
	ushort	tca__pad2;
}

rtattr* TA_RTA(tcamsg* r) {
	return (cast(rtattr*)((cast(char*)r) + NLMSG_ALIGN(tcamsg.sizeof)));
}
uint TA_PAYLOAD(uint n) {
	return NLMSG_PAYLOAD(n,tcamsg.sizeof);
}
enum TCA_ACT_TAB = 1; /* attr type must be >=1 */	
enum TCAA_MAX = 1;

/* New extended info filters for IFLA_EXT_MASK */
enum {
	RTEXT_FILTER_VF		= (1 << 0),
	RTEXT_FILTER_BRVLAN	= (1 << 1),
	RTEXT_FILTER_BRVLAN_COMPRESSED	= (1 << 2),
	RTEXT_FILTER_SKIP_STATS	 = (1 << 3)
}
/* End of information exported to user level */

