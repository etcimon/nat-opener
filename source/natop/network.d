module natop.network;

import core.exception : onOutOfMemoryError;
import vibe.core.net;

import std.exception;
import std.string : fromStringz;
import std.conv : to;
import std.array : Appender;
import core.stdc.stdlib : malloc, free;

version(Windows) {
import windows.windows;
import windows.iptypes;
import windows.iphlpapi;
}
version(Posix)
	import core.sys.posix.arpa.inet;

enum LOG = true;

struct IPRoute {
	NetworkAddress destination;
	NetworkAddress gateway;
	NetworkAddress netmask;
	string name;

	string toString() {
		return "['" ~ destination.toAddressString() ~ "', '" ~ gateway.toAddressString() ~ "', '" ~ netmask.toAddressString() ~ "']";
	}
}

version(Windows)
IPRoute[] getDeviceListing() {

	Appender!(IPRoute[]) ret;
	ret.reserve(4);

	PIP_ADAPTER_INFO adapter_info;
	ULONG out_buf_size;

	if (GetAdaptersInfo(adapter_info, &out_buf_size) != ERROR_BUFFER_OVERFLOW)
		throw new Exception("Operation not supported: " ~ GetAdaptersInfo(adapter_info, &out_buf_size).to!string);
	adapter_info = cast(IP_ADAPTER_INFO*)malloc(out_buf_size);
	
	if (!adapter_info)
		onOutOfMemoryError();
	
	scope(exit) 
		free(adapter_info);
	DWORD ec = GetAdaptersInfo(adapter_info, &out_buf_size);
	enforce(ec == NO_ERROR, format("Got error: %s", ec.to!string));

	for (PIP_ADAPTER_INFO adapter = adapter_info; adapter !is null; adapter = adapter.Next)
	{
		auto gateway = cast(string)adapter.GatewayList.IpAddress.String.ptr.fromStringz();
		if (gateway == "0.0.0.0") continue;
		IPRoute r;
		r.destination = resolveHost(cast(string)adapter.IpAddressList.IpAddress.String.ptr.fromStringz(), AF_INET, false);
		r.gateway = resolveHost(gateway, AF_INET, false);
		r.netmask = resolveHost(cast(string)adapter.IpAddressList.IpMask.String.ptr.fromStringz(), AF_INET, false);
		r.name = adapter.AdapterName.ptr.fromStringz().idup;

		ret ~= r;
	}

	return ret.data;
}

version(linux) {
	import natop.internals.netlink;
	import natop.internals.rtnetlink;
	import core.stdc.stdlib;
	import core.sys.linux.sys.socket;
	import core.sys.posix.sys.socket;

	int readNetLink(size_t BUFSIZE)(int nl_sock, ref ubyte[BUFSIZE] buf)
	{
		nlmsghdr* nl_hdr;		
		int msg_len;		
		do {
			int read_len = recv(nl_sock, buf.ptr, BUFSIZE - msg_len, 0);
			if (read_len < 0) return -1;

			nl_hdr = cast(nlmsghdr*)buf.ptr;
			
			if ((NLMSG_OK(nl_hdr, cast(uint) read_len) == 0) || (nl_hdr.nlmsg_type == NLMSG_ERROR))
				return -1;
			
			if (nl_hdr.nlmsg_type == NLMSG_DONE) break;
			
			buf = buf[read_len .. $];
			msg_len += read_len;
			
			if ((nl_hdr.nlmsg_flags & NLM_F_MULTI) == 0) break;
			
		} while(nl_hdr.nlmsg_seq < 1 || nl_hdr.nlmsg_pid != cast(uint)getpid());

		return msg_len;
	}

	bool parseRoute(nlmsghdr* nl_hdr, ref IPRoute rt_info)
	{
		rtmsg* rt_msg = cast(rtmsg*)NLMSG_DATA(nl_hdr);
		
		if ((rt_msg.rtm_family != AF_INET) || (rt_msg.rtm_table != RT_TABLE_MAIN))
			return false;
		
		int rt_len = RTM_PAYLOAD(nl_hdr);
		for (rtattr* rt_attr = cast(rtattr*)RTM_RTA(rt_msg);
			RTA_OK(rt_attr,rt_len); rt_attr = RTA_NEXT(rt_attr,rt_len))
		{
			switch(rt_attr.rta_type)
			{
				case RTA_OIF:
					if_indextoname(*cast(int*)RTA_DATA(rt_attr), rt_info.name);
					break;
				case RTA_GATEWAY:
					rt_info.gateway.family = AF_INET;
					rt_info.gateway.sockAddrInet4.sin_addr.s_addr = (ntohl(*cast(uint*)RTA_DATA(rt_attr)));
					break;
				case RTA_DST:
					rt_info.destination.family = AF_INET;
					rt_info.destination.sockAddrInet4.sin_addr.s_addr = (ntohl(*cast(uint*)RTA_DATA(rt_attr)));
					break;
			}
		}
		return true;
	}

	IPRoute[] getDeviceListing() {
		
		Appender!(IPRoute[]) ret;
		ret.reserve(4);

		int sock = socket(PF_ROUTE, SOCK_DGRAM, NETLINK_ROUTE);
		errnoEnforce(sock >= 0);

		scope(exit) close(sock);

		ubyte[8192] msg;
		memset(msg.ptr, 0, msg.sizeof);

		nlmsghdr* nl_msg = cast(nlmsghdr*) msg.ptr;
		
		nl_msg.nlmsg_len = NLMSG_LENGTH(rtmsg.sizeof);
		nl_msg.nlmsg_type = cast(ushort) RTM_GETROUTE;
		nl_msg.nlmsg_flags = cast(ushort) (NLM_F_DUMP | NLM_F_REQUEST);
		nl_msg.nlmsg_seq = 0;
		nl_msg.nlmsg_pid = cast(uint) getpid();

		errnoEnforce(send(sock, nl_msg, nl_msg.nlmsg_len, 0) >= 0);
		
		int len = readNetLink(sock, msg);
		errnoEnforce(len >= 0);
		
		while (NLMSG_OK(nl_msg, cast(uint)len))
		{
			IPRoute r;
			if (parseRoute(nl_msg, r))
				ret.put(r);
			nl_msg = NLMSG_NEXT(nl_msg, cast(uint)len);
		}
		return ret.data;
	}

}

version(OSX)
	IPRoute[] getDeviceListing() {
	
	Appender!(IPRoute[]) ret;
	ret.reserve(4);
	
	return ret.data;
	
}


interface Router {
	@property string id();

	@property bool hasDevice();

	void discover();

	void deleteMapping(ushort external_port, bool is_tcp = true);

	void createMapping(ushort local_port, ushort external_port, bool is_tcp = true);
}
