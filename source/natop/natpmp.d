module natop.natpmp;

import natop.network;
import natop.exceptions;

import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import std.conv;
import std.exception;
import std.random;
import std.datetime;

import memutils.vector;

import vibe.core.core;
import vibe.core.net;
import vibe.core.log;

class NATPMP : Router {
private:	
	Vector!ubyte m_bytes;
	UDPConnection m_udp;
	bool m_hasDevice;
	IPRoute m_iproute;

public:
	@property string id() const {
		return m_iproute.gateway.toAddressString();
	}

	@property bool hasDevice() {
		return m_hasDevice;
	}

	this(IPRoute iproute) {
		m_iproute = iproute;
		bool has_error;
		int retries;
		do {
			
			has_error = false;
			ushort port = uniform(2000,65000).to!ushort;
			try { 
				m_udp = listenUDP(port, iproute.destination.toAddressString());
			}
			catch (Exception e) {
				logError("Could not bind to port [%d]: %s", port, e.msg);
				has_error = true;
				sleep(100.msecs);
			}
			enforce(++retries < 2);
		} while (has_error);
		m_udp.connect(iproute.gateway.toAddressString(), 5351);
	}

	~this() {
		try m_udp.close(); catch (Exception e) {
			logError("Error in NAT-PMP Dtor: %s", e.msg);
		}
	}

	void discover() {
		int retries;
		// send a request and watch for error
		while (++retries < 2) {
			ushort trial_port = cast(ushort) uniform(10000,63000);
			ubyte[12] buf = buildRequest(trial_port, true);
			m_udp.send(buf.ptr[0 .. 12]);
			try readResponse();
			catch (NATPMPException e) {
				logError("Error in NATPMP discover: %s", e.msg);
				return;
			}
			catch (TimeoutException e) {
				logError("Timeout in NATPMP discover: %s", e.msg);
				continue;
			}
			catch (Exception e) {
				logError("Generic Error in NATPMP discover: %s", e.msg);
				return;
			}

			m_hasDevice = true;

			// remove dummy port redirect
			try {
				buf = buildRequest(trial_port, true, false);
				m_udp.send(buf.ptr[0 .. 12]);
				readResponse();
			} catch (Exception e) {
				logError("Failed to remove dummy port redirect: %s", e.msg);
			}
			return;
		}
	}

	void createMapping(ushort local_port, ushort external_port, bool is_tcp = true) {
		ubyte[12] buf = buildRequest(external_port, is_tcp);
		m_udp.send(buf.ptr[0 .. 12]);
		readResponse();
	}

	void deleteMapping(ushort external_port, bool is_tcp = true) {

		ubyte[12] buf = buildRequest(external_port, is_tcp, false);
		m_udp.send(buf.ptr[0 .. 12]);
		readResponse();
	}
private:
	ubyte[12] buildRequest(ushort external_port, bool is_tcp, bool adding = true) {
		ubyte[12] buf;
		size_t pos;

		buf[pos .. pos+1] = nativeToBigEndian!ubyte(0); ++pos;
		buf[pos .. pos+1] = nativeToBigEndian!ubyte(is_tcp?2:1); ++pos;
		buf[pos .. pos+2] = nativeToBigEndian!ushort(0); pos+=2;
		buf[pos .. pos+2] = nativeToBigEndian!ushort(external_port); pos+=2;
		buf[pos .. pos+2] = nativeToBigEndian!ushort(external_port); pos+=2;
		buf[pos .. pos+4] = nativeToBigEndian!uint(adding?3600:0);

		return buf;
	}

	void readResponse() {
		size_t pos;
		ubyte[16] data;
		m_udp.recv(1.seconds, data.ptr[0 .. 16]);
		ubyte version_ = bigEndianToNative!ubyte(*cast(ubyte[1]*)(data.ptr+pos)); ++pos;
		ubyte cmd = bigEndianToNative!ubyte(*cast(ubyte[1]*)(data.ptr+pos)); ++pos;
		ushort result = bigEndianToNative!ushort(*cast(ubyte[2]*)(data.ptr+pos)); pos+=2;
		uint time = bigEndianToNative!uint(*cast(ubyte[4]*)(data.ptr+pos)); pos+=4;
		ushort private_port = bigEndianToNative!ushort(*cast(ubyte[2]*)(data.ptr+pos)); pos+=2;
		ushort public_port = bigEndianToNative!ushort(*cast(ubyte[2]*)(data.ptr+pos)); pos+=2;
		uint lifetime = bigEndianToNative!uint(*cast(ubyte[4]*)(data.ptr+pos));

		bool is_tcp = (cmd - 128 == 1)?false:true;

		static if (LOG) logInfo("Got version %d, cmd %d, result %d, time %d, private_port %d, public_port %d, lifetime %d, is_tcp %s",
			version_, cmd, result, time, private_port, public_port, lifetime, is_tcp.to!string);

		// validate
		enforce(version_ == 0, "Invalid NAT-PMP version: " ~ version_.to!string);

		if (result != 0) {
			string[] errors = [
				"Unsupported protocol version",
				"Not authorized to create port map (enable NAT-PMP on your router)",
				"Network failure",
				"Out of resources",
				"Unsupported opcode"
			];
			throw new NATPMPException(errors[result-1]);
		}
	}
}

