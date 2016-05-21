module natop.internals.netlink;

version (linux):

extern (C):
@system:
nothrow:

import core.sys.posix.sys.types;


enum {
	NETLINK_ROUTE		= 0,	/* Routing/device hook				*/
	NETLINK_UNUSED		= 1,	/* Unused number				*/
	NETLINK_USERSOCK	= 2,	/* Reserved for user mode socket protocols 	*/
	NETLINK_FIREWALL	= 3,	/* Unused number, formerly ip_queue		*/
	NETLINK_SOCK_DIAG	= 4,	/* socket monitoring				*/
	NETLINK_NFLOG		= 5,	/* netfilter/iptables ULOG */
	NETLINK_XFRM		= 6,	/* ipsec */
	NETLINK_SELINUX		= 7,	/* SELinux event notifications */
	NETLINK_ISCSI		= 8,	/* Open-iSCSI */
	NETLINK_AUDIT		= 9,	/* auditing */
	NETLINK_FIB_LOOKUP	= 10,	
	NETLINK_CONNECTOR	= 11,
	NETLINK_NETFILTER	= 12,	/* netfilter subsystem */
	NETLINK_IP6_FW		= 13,
	NETLINK_DNRTMSG		= 14,	/* DECnet routing messages */
	NETLINK_KOBJECT_UEVENT	= 15,	/* Kernel messages to userspace */
	NETLINK_GENERIC		= 16,
	/* leave room for NETLINK_DM (DM Events) */
	NETLINK_SCSITRANSPORT	= 18,	/* SCSI Transports */
	NETLINK_ECRYPTFS	= 19,
	NETLINK_RDMA		= 20,
	NETLINK_CRYPTO		= 21,	/* Crypto layer */
	
	NETLINK_INET_DIAG	= NETLINK_SOCK_DIAG
}

enum MAX_LINKS = 32;
	
alias __kernel_sa_family_t = ushort;

struct sockaddr_nl {
	__kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
	ushort	nl_pad;		/* zero		*/
	uint		nl_pid;		/* port ID	*/
	uint		nl_groups;	/* multicast groups mask */
}

struct nlmsghdr {
	uint		nlmsg_len;	/* Length of message including header */
	ushort		nlmsg_type;	/* Message content */
	ushort		nlmsg_flags;	/* Additional flags */
	uint		nlmsg_seq;	/* Sequence number */
	uint		nlmsg_pid;	/* Sending process port ID */
}

/* Flags values */

enum {
	NLM_F_REQUEST	= 1,	/* It is request message. 	*/
	NLM_F_MULTI		= 2,	/* Multipart message, terminated by NLMSG_DONE */
	NLM_F_ACK		= 4,	/* Reply with ack, with zero or error code */
	NLM_F_ECHO		= 8,	/* Echo this request 		*/
	NLM_F_DUMP_INTR		= 16,	/* Dump was inconsistent due to sequence change */
	NLM_F_DUMP_FILTERED	= 32	/* Dump was filtered as requested */
}
/* Modifiers to GET request */
enum {
	NLM_F_ROOT	= 0x100,	/* specify tree	root	*/
	NLM_F_MATCH	= 0x200,	/* return all matching	*/
	NLM_F_ATOMIC	= 0x400,	/* atomic GET		*/
	NLM_F_DUMP	= (NLM_F_ROOT|NLM_F_MATCH)
}
/* Modifiers to NEW request */
enum {
	NLM_F_REPLACE	= 0x100,	/* Override existing		*/
	NLM_F_EXCL		= 0x200,	/* Do not touch, if it exists	*/
	NLM_F_CREATE	= 0x400,	/* Create, if it does not exist	*/
	NLM_F_APPEND	= 0x800	/* Add to end of list		*/
}

/*
   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
   4.4BSD CHANGE	NLM_F_REPLACE

   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
   Append		NLM_F_CREATE
   Check		NLM_F_EXCL
 */

enum NLMSG_ALIGNTO = 4u;

uint NLMSG_ALIGN(uint len) {
	return  ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) );
}
enum NLMSG_HDRLEN	= (cast(int) NLMSG_ALIGN(nlmsghdr.sizeof));
uint NLMSG_LENGTH()(auto len) {
	return ((len) + NLMSG_HDRLEN);
}

uint NLMSG_SPACE(auto len) {
	return NLMSG_ALIGN(NLMSG_LENGTH(len));
}
void* NLMSG_DATA(nlmsghdr* nlh) {
	return (cast(void*)((cast(char*)nlh) + NLMSG_LENGTH(0)));
} 
nlmsghdr* NLMSG_NEXT(nlmsghdr* nlh, ref uint len){
	len -= NLMSG_ALIGN(nlh.nlmsg_len);
	return cast(nlmsghdr*)((cast(char*)(nlh)) + NLMSG_ALIGN(nlh.nlmsg_len));
}

bool NLMSG_OK(nlmsghdr* nlh, uint len) {
	return (len >= cast(int)nlmsghdr.sizeof && 
		nlh.nlmsg_len >= nlmsghdr.sizeof && 
		nlh.nlmsg_len <= len);
}

uint NLMSG_PAYLOAD(nlmsghdr* nlh, uint len) {
	return (nlh.nlmsg_len - NLMSG_SPACE(len));
}

enum {
	NLMSG_NOOP		= 0x1,	/* Nothing.		*/
	NLMSG_ERROR		= 0x2,	/* Error		*/
	NLMSG_DONE		= 0x3,	/* End of a dump	*/
	NLMSG_OVERRUN		= 0x4,	/* Data lost		*/
	NLMSG_MIN_TYPE		= 0x10	/* < 0x10: reserved control messages */
}

struct nlmsgerr {
	int		error;
	nlmsghdr msg;
}

enum {
	NETLINK_ADD_MEMBERSHIP		= 1,
	NETLINK_DROP_MEMBERSHIP		= 2,
	NETLINK_PKTINFO			= 3,
	NETLINK_BROADCAST_ERROR		= 4,
	NETLINK_NO_ENOBUFS		= 5,
	
	NETLINK_RX_RING			= 6,
	NETLINK_TX_RING			= 7,
	
	NETLINK_LISTEN_ALL_NSID		= 8,
	NETLINK_LIST_MEMBERSHIPS	= 9,
	NETLINK_CAP_ACK			= 10
}

struct nl_pktinfo {
	uint	group;
}

struct nl_mmap_req {
	uint	nm_block_size;
	uint	nm_block_nr;
	uint	nm_frame_size;
	uint	nm_frame_nr;
}

struct nl_mmap_hdr {
	uint		nm_status;
	uint		nm_len;
	uint		nm_group;
	/* credentials */
	uint		nm_pid;
	uint		nm_uid;
	uint		nm_gid;
}

enum nl_mmap_status {
	NL_MMAP_STATUS_UNUSED,
	NL_MMAP_STATUS_RESERVED,
	NL_MMAP_STATUS_VALID,
	NL_MMAP_STATUS_COPY,
	NL_MMAP_STATUS_SKIP,
}

enum NL_MMAP_MSG_ALIGNMENT	= NLMSG_ALIGNTO;

uint __ALIGN_KERNEL(uint x, uint a) {
	return __ALIGN_KERNEL_MASK(x, a - 1);
}

uint __ALIGN_KERNEL_MASK(auto x, auto mask) {
	return (((x) + (mask)) & ~(mask));
}

uint NL_MMAP_MSG_ALIGN(uint sz)	{
	return __ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT);
}

enum NL_MMAP_HDRLEN	= NL_MMAP_MSG_ALIGN(nl_mmap_hdr.sizeof);

enum NET_MAJOR = 36;		/* Major 36 is reserved for networking 						*/

enum {
	NETLINK_UNCONNECTED = 0,
	NETLINK_CONNECTED,
}

/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

struct nlattr {
	ushort           nla_len;
	ushort           nla_type;
}

/*
 * nla_type (16 bits)
 * +---+---+-------------------------------+
 * | N | O | Attribute Type                |
 * +---+---+-------------------------------+
 * N := Carries nested attributes
 * O := Payload stored in network byte order
 *
 * Note: The N and O flag are mutually exclusive.
 */
enum NLA_F_NESTED	= (1 << 15);
enum NLA_F_NET_BYTEORDER	= (1 << 14);
enum NLA_TYPE_MASK		= ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

enum NLA_ALIGNTO		= 4;
uint NLA_ALIGN(uint len) {
	return ((len + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)); 
}
uint NLA_HDRLEN = NLA_ALIGN(nlattr.sizeof);