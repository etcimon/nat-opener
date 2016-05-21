module natop.upnp;

import natop.network;
import natop.exceptions;

import std.random : uniform;
import std.datetime;
import std.exception;
import std.algorithm;
import std.conv;
import std.string;


import vibe.core.core;
import vibe.core.net;
import vibe.core.log;
import vibe.stream.operations;
import vibe.http.common;
import vibe.inet.message;
import vibe.utils.memory;
import vibe.http.client;
import vibe.stream.memory;

import kxml.xml;

private string g_userAgent = "NAT-Opener/1.0.0";

void setUserAgent(string ua) {
	g_userAgent = ua;
}

class UPNP : Router {
private:
	string m_baseURL;
	UDPConnection m_udp;
	IPRoute m_iproute;
	XmlNode m_device;

public:
	@property string id() {
		return getXmlNodeValue("UDN").replace("uuid:", "").strip();

	}

	@property bool hasDevice() const {
		return m_device !is null;
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
			}
			enforce(++retries < 100);
		} while (has_error);
		retries = 0;
		while(!m_udp.canBroadcast || has_error) {
			has_error = false;
			try {
				m_udp.canBroadcast = true;
			} catch (Exception e) {
				has_error = true;
				sleep(1.seconds);
			}
			enforce (++retries < 10);
		}
		m_udp.connect("239.255.255.250", 1900);
	}

	~this() {
		try m_udp.close(); catch (Exception e) {
			logError("Error in UPNP Dtor: %s", e.msg);
		}
	}

	void discover() {
		string query = "M-SEARCH * HTTP/1.1\r\n"
				"HOST: 239.255.255.250:1900\r\n"
				"ST: upnp:rootdevice\r\n"
				"MAN: ssdp:discover\r\n"
				"MX: 1\r\n\r\n";
		ubyte[] data = new ubyte[](4096);
		auto start = Clock.currTime(UTC());

		while(Clock.currTime(UTC()) - start < 5.seconds) {
			m_udp.send(cast(ubyte[])query);
			NetworkAddress peer;
			// wait for packet up to 1 sec
			ubyte[] bytes = m_udp.recv(1.seconds, data, &peer);

			static if (LOG) logInfo("Discover response received from %s: %s", peer.toString(), cast(string)bytes);

			if (peer.toAddressString() != m_iproute.gateway.toAddressString()) {
				static if (LOG) logInfo("Got unmatched peer: %s != %s", peer.toAddressString(), m_iproute.gateway.toAddressString());
				continue;
			}
			if (peer.port == 0) {
				static if (LOG) logInfo("Got zero port");
				continue;
			}

			// process packet
			if (handlePacket(bytes))
				break;
		}
	}

	void deleteMapping(ushort external_port, bool is_tcp = true) {
		string soap_action = "DeletePortMapping";
		string query = format(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" 
s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:%s xmlns:u="%s">
<NewExternalPort>%u</NewExternalPort>
<NewProtocol>%s</NewProtocol>
</u:%s></s:Body></s:Envelope>`, 
			soap_action, serviceType, external_port, 
			(is_tcp ? "TCP":"UDP"), soap_action);
		
		
		string response_data;
		requestHTTP(controlURL, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.httpVersion = HTTPVersion.HTTP_1_0;
				req.headers.remove("Accept-Encoding");
				req.headers.remove("Connection");
				req.headers["Soapaction"] = "\"" ~ serviceType ~ "#" ~ soap_action ~ "\"";
				req.writeBody(query, "text/xml; charset=\"utf-8\"");
			}, (scope HTTPClientResponse res) {
				enforce(res.statusCode == 200, "Mapping failed: " ~ res.statusPhrase);
				response_data = cast(string)res.bodyReader.readAll();
				static if (LOG) logInfo("Tried to delete mapping, got: %s", response_data);
			});
		validateMappingResponse(readDocument(response_data));
	}
	
	void createMapping(ushort local_port, ushort external_port, bool is_tcp = true) {
		static if (LOG) logInfo("Creating mapping");
		string soap_action = "AddPortMapping";
		string query = format(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" 
	s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:%s xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%u</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%u</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:%s></s:Body></s:Envelope>`, soap_action, serviceType, external_port,
			(is_tcp ? "TCP":"UDP"),
			local_port, m_iproute.destination.toAddressString(), g_userAgent, soap_action);
		
		string response_data;
		static if (LOG) logInfo("Control URL: %s", controlURL);
		static if (LOG) logInfo("Query: %s", query);
		requestHTTP(controlURL, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.httpVersion = HTTPVersion.HTTP_1_0;
				req.headers.remove("Accept-Encoding");
				req.headers.remove("Connection");
				req.headers["Soapaction"] = "\"" ~ serviceType ~ "#" ~ soap_action ~ "\"";
				req.writeBody(query, "text/xml; charset=\"utf-8\"");				
			}, (scope HTTPClientResponse res) {
				enforce(res.statusCode == 200, "Mapping failed: " ~ res.statusPhrase);
				response_data = cast(string)res.bodyReader.readAll();
				static if (LOG) logInfo("Tried to create mapping, got: %s", response_data);
			});
		validateMappingResponse(readDocument(response_data));
	}
private:

	@property string serviceType() {
		return getXmlNodeValue("serviceType");
	}
	
	@property string controlURL() {
		string ctl_url = getXmlNodeValue("controlURL");
		enforce(ctl_url.length > 0, "No Control URL Found");
		if (ctl_url[0] == '/')
			return m_baseURL ~ ctl_url;
		return ctl_url;
	}
	
	string getXmlNodeValue(string key) {
		XmlNode[] matches = m_device.parseXPath("//" ~ key);
		enforce(matches.length > 0, "No " ~ key ~ " found for Device");
		return matches[0].getCData();
	}
	bool handlePacket(ubyte[] bytes) {

		auto bytes_stream = new MemoryStream(bytes, false);
		string stln = cast(string)readLine(bytes_stream, 4096, "\r\n", defaultAllocator());
		auto httpVersion = parseHTTPVersion(stln);		
		enforce(stln.startsWith(" "));
		stln = stln[1 .. $];
		auto statusCode = parse!int(stln);

		if (statusCode != 200)
			return false;

		string statusPhrase;
		if( stln.length > 0 ){
			enforce(stln.startsWith(" "));
			stln = stln[1 .. $];
			statusPhrase = stln;
		}

		InetHeaderMap headers;
		// read headers until an empty line is hit
		parseRFC5322Header(bytes_stream, headers, 4096, defaultAllocator(), false);

		if (headers.get("ST").indexOf("rootdevice", CaseSensitive.no) == -1)
			return false;
		if (headers.get("USN").indexOf("rootdevice", CaseSensitive.no) == -1)
			return false;
		XmlNode xml_doc;
		URL base_url = URL.parse(headers.get("Location"));
		m_baseURL = format("%s://%s:%d", base_url.schema, base_url.host, base_url.port);
		requestHTTP(headers.get("Location"), (scope HTTPClientRequest req) {
				req.httpVersion = HTTPVersion.HTTP_1_0;
			}, (scope HTTPClientResponse res) {
				auto response_text = cast(string) res.bodyReader().readAll();
				xml_doc = readDocument(response_text);
			});
		//if (xml_doc) static if (LOG) logInfo("Got document: %s", xml_doc.toPrettyString());

		m_device = findInternetDevice(xml_doc);
		if (m_device) static if (LOG) logInfo("Got device: %s", m_device.toPrettyString());
		return m_device !is null;

	}

	XmlNode findInternetDevice(XmlNode xml_doc) {
		XmlNode[] list = xml_doc.parseXPath("//device");
		foreach (i, XmlNode el; list) {
			XmlNode[] service_types = el.parseXPath("/serviceList/service/serviceType");
			if (service_types.length > 0) {
				string service_type = service_types[0].getCData();
				static if (LOG) logInfo("Service type: %s", service_type);
				if (service_type.indexOf("WANIPConnection", CaseSensitive.no) != -1 || service_type.indexOf("WANPPPConnection", CaseSensitive.no) != -1)
					return el;
			}
		}
		return null;
	}


	void validateMappingResponse(XmlNode response_xml) {
		XmlNode[] xml_error_code = response_xml.parseXPath("//errorCode");
		if (xml_error_code.length == 0) return;

		int error_code = xml_error_code[0].getCData().to!int;
		// handle errors

		switch (error_code)
		{
			case 725:
				// permanent leases only
				throw new NATOPException("Lease durations unsupported in the router");
			case 718:
			case 727:
				// conflict in mapping
				throw new PortConflictException(getUPNPError(727));
			case 716:
				// cannot be wildcard on external port, use random
				throw new NATOPException("Wildcard ports unsupported in the router");
			default:
				string error_msg = getUPNPError(error_code);

				XmlNode[] xml_error_msg = response_xml.parseXPath("//errorDescription");
				if (xml_error_msg.length > 0)
					error_msg = xml_error_msg[0].getCData();

				throw new NATOPException(format("Got Error %d: %s", error_code, error_msg));
		}

	}

}

struct UPNPErrorCode
{
	int code;
	string msg;
}

package:

UPNPErrorCode[] g_errorCodes = [
	{402, "Invalid Arguments"},
	{501, "Action Failed"},
	{714, "The specified value does not exist in the array"},
	{715, "The source IP address cannot be wild-carded"},
	{716, "The external port cannot be wild-carded"},
	{718, "The port mapping entry specified conflicts with a mapping assigned previously to another client"},
	{724, "Internal and External port values must be the same"},
	{725, "The NAT implementation only supports permanent lease times on port mappings"},
	{726, "RemoteHost must be a wildcard and cannot be a specific IP address or DNS name"},
	{727, "ExternalPort must be a wildcard and cannot be a specific port "}
];

string getUPNPError(int code) {
	foreach (error; g_errorCodes) {
		if (error.code == code)
			return error.msg;
	}
	return "";
}