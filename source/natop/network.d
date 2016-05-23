module natop.network;

import core.exception : onOutOfMemoryError;
import vibe.core.net;
import vibe.core.log;

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
	import std.string;
	import core.stdc.stdlib;
	import core.stdc.string;
	import core.sys.linux.sys.socket;
	import core.sys.posix.sys.socket;
	import core.sys.posix.net.if_;
	import core.sys.posix.unistd;
	int readNetLink(size_t BUFSIZE)(int nl_sock, ref ubyte[BUFSIZE] buf)
	{
		nlmsghdr* nl_hdr;		
		int msg_len;
		ubyte* pbuf = buf.ptr;	
		do {
			int read_len = cast(int)recv(nl_sock, pbuf, BUFSIZE - msg_len, 0);
			if (read_len < 0) return -1;

			nl_hdr = cast(nlmsghdr*)pbuf;
			
			if ((NLMSG_OK(nl_hdr, cast(uint) read_len) == 0) || (nl_hdr.nlmsg_type == NLMSG_ERROR))
				return -1;
			
			if (nl_hdr.nlmsg_type == NLMSG_DONE) break;
			
			pbuf += read_len;
			msg_len += read_len;
			
			if ((nl_hdr.nlmsg_flags & NLM_F_MULTI) == 0) break;
			
		} while(nl_hdr.nlmsg_seq < 1 || nl_hdr.nlmsg_pid != cast(uint)getpid());

		return msg_len;
	}

	void parseRoute(nlmsghdr* nl_hdr, ref IPRoute[string] ip_route_map)
	{
		rtmsg* rt_msg = cast(rtmsg*)NLMSG_DATA(nl_hdr);
		
		if ((rt_msg.rtm_family != AF_INET) || (rt_msg.rtm_table != RT_TABLE_MAIN))
			return;
		
		uint rt_len = RTM_PAYLOAD(nl_hdr);
		IPRoute rt_info;
		for (rtattr* rt_attr = cast(rtattr*)RTM_RTA(rt_msg);
			RTA_OK(rt_attr,rt_len); rt_attr = RTA_NEXT(rt_attr,rt_len))
		{
			switch(rt_attr.rta_type)
			{
				case RTA_OIF:
					char[64] name;
					if_indextoname(cast(uint)*cast(int*)RTA_DATA(rt_attr), name.ptr);
					rt_info.name = name.ptr.fromStringz.idup;
					logInfo("Got name: %s", rt_info.name);
					break;
				case RTA_GATEWAY:
					rt_info.gateway.family = AF_INET;
					rt_info.gateway.sockAddrInet4.sin_addr.s_addr = ((*cast(uint*)RTA_DATA(rt_attr)));
					logInfo("Got gateway: %s", rt_info.gateway.toAddressString());
					break;
				case RTA_DST:
					rt_info.destination.family = AF_INET;
					rt_info.destination.sockAddrInet4.sin_addr.s_addr = ((*cast(uint*)RTA_DATA(rt_attr)));
					logInfo("Got destination: %s", rt_info.destination.toAddressString());
					break;
				default:
					break;
			}
		}
		if (auto ptr = rt_info.name in ip_route_map) {
			if (ptr.destination.family == AF_INET)
				ptr.gateway = rt_info.gateway;
			else
				ptr.destination = rt_info.destination;
		} else ip_route_map[rt_info.name] = rt_info;
		
	}

	IPRoute[] getDeviceListing() {
		
		Appender!(IPRoute[]) ret;
		enum PF_ROUTE = 16;
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
		uint ulen = cast(uint) len;
		IPRoute[string] routes;
		while (NLMSG_OK(nl_msg, ulen))
		{
			parseRoute(nl_msg, routes);
			nl_msg = NLMSG_NEXT(nl_msg, ulen);
		}

		foreach (string name, IPRoute route; routes)
			if (route.gateway.family == AF_INET && route.destination.family == AF_INET)
			{
				logInfo("Appending %s", name);
				logInfo("Gateway: %s", route.gateway.toAddressString());
				logInfo("Destination: %s", route.destination.toAddressString());
				ret ~= route;
			}
		logInfo("Returning %d items", ret.data.length);
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
