module natop.network;

import core.exception : onOutOfMemoryError;
import vibe.core.net;

import std.exception;
import std.string : fromStringz;
import std.conv : to;
import std.array : Appender;
import core.stdc.stdlib : malloc, free;

import windows.windows;
import windows.iptypes;
import windows.iphlpapi;

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
	enforce(ec == NO_ERROR, "Got error: " ~ ec.to!string);

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

interface Router {
	@property string id();

	@property bool hasDevice();

	void discover();

	void deleteMapping(ushort external_port, bool is_tcp = true);

	void createMapping(ushort local_port, ushort external_port, bool is_tcp = true);
}