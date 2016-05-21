module natop.opener;

import natop.network;
import natop.upnp;
import natop.natpmp;
import natop.exceptions;
import vibe.core.core;
import vibe.core.log;
import vibe.http.server;

import std.datetime;
import std.string : format;
import std.stdio: writeln;
import std.algorithm : remove;
import std.array : array;
// returns false on error
private Router[string] g_routers;
private Mapping[][string] g_registeredMappings;
private Mapping[] g_mappings;


struct Mapping {
	ushort external_port;
	bool is_tcp;
}

// ports must be closed before application exit
void open(ushort port, bool is_tcp) {
	foreach (mapping; g_mappings)
		if (mapping.external_port == port && mapping.is_tcp == is_tcp)
			throw new NATOPException(format("Mapping already created: %d, %s", port, is_tcp?"TCP":"UDP"));
	static if (LOG) logInfo("Opening port: %d", port);
	foreach (string id, Router router; g_routers) {
		int retries;
		do {
			try {
				router.createMapping(port, port, is_tcp);
				g_registeredMappings[id] ~= Mapping(port, is_tcp);
			}
			catch (Exception e) {
				logError("Could not create mapping in router: %s", e.msg);
			}
		} while (++retries < 3);
	}

	g_mappings ~= Mapping(port, is_tcp);
}

void close(ushort port, bool is_tcp) {
	// foreach device, delete mapping

	size_t to_delete;
	bool deleted;
	{
		foreach (i, Mapping mapping; g_mappings) {
			if (mapping.external_port == port && mapping.is_tcp == is_tcp)
			{
				to_delete = i;
				deleted = true;
				break;
			}
		}
		if (deleted) {
			g_mappings = g_mappings.remove(to_delete).array.to!(Mapping[]);
		}
	}
	foreach (string router_id, Mapping[] mappings; g_registeredMappings) {
		deleted = false;
		to_delete = 0;
		foreach (i, mapping; mappings) {
			if (mapping.external_port == port && mapping.is_tcp == is_tcp)
			{
				try {
					static if (LOG) logInfo("Deleting mapping in close for port %d", port);
					g_routers[router_id].deleteMapping(mapping.external_port, mapping.is_tcp);
					to_delete = i;
					deleted = true;
				}
				catch (Exception e) logError("Could not delete mapping: %s", e.msg);
				break;
			}
		}
		if (deleted)
			g_registeredMappings[router_id] = mappings.remove(to_delete).array.to!(Mapping[]);

	}
	static if (LOG) logInfo("Now have registered mappings: %s", g_registeredMappings.to!string);
	static if (LOG) logInfo("Mappings: %s", g_mappings.to!string);
}

void discover() {
	Router[string] new_routers;
	Appender!(Task[]) tasks;
	foreach (iproute; getDeviceListing()) {

		// interrupt the other when one completes a successful port redirect
		auto mtx = new InterruptibleTaskMutex();
		Task upnp_task;
		Task natpmp_task;
		scope(success) { tasks ~= upnp_task; tasks ~= natpmp_task; }
		bool mapping_exists;
		void createMappings(Router router) {
			// remember this device to open ports on it when necessary
			new_routers[router.id] = router;
			static if (LOG) logInfo("Done discovery");
			if (router.id !in g_registeredMappings) {
				// open the ports on this router
				foreach (mapping; g_mappings) {
					router.createMapping(mapping.external_port, mapping.external_port, mapping.is_tcp);
					g_registeredMappings[router.id] ~= mapping;
				}
			}
			else mapping_exists = true;
		}

		upnp_task = runTask({
				auto upnp = new UPNP(iproute);
				scope(failure) upnp.destroy();
				try upnp.discover();
				catch (Exception e) {
					logError("Error with UPNP in gateway %s: %s", iproute.gateway.toString(), e.msg);
					//static if (LOG) logInfo("%s", e.toString());
				}
				if (upnp.hasDevice()) {
					synchronized(mtx) {
						if (!mapping_exists) {
							int retry;
							do {
								try createMappings(upnp);
								catch (Exception e) { logError("Error creating mapping: %s", e.msg); }

							} while (++retry < 3);
							// interrupt the other one
							if (natpmp_task != Task())
								natpmp_task.interrupt();
						}
					}
				}
				upnp_task = Task();
			});

		natpmp_task = runTask({
				auto natpmp = new NATPMP(iproute);
				scope(failure) natpmp.destroy();
				try natpmp.discover();
				catch (Exception e) {
					logError("Error with NATPMP in gateway %s: %s", iproute.gateway.toString(), e.msg);
					static if (LOG) logInfo("%s", e.toString());
				}
				if (natpmp.hasDevice) {
					synchronized(mtx) {
						if (!mapping_exists) {
							createMappings(natpmp);
							// interrupt the other one
							if (upnp_task != Task())
								upnp_task.interrupt();
						}
					}
				}
				static if (LOG) logInfo("NATPMP has device: %s", natpmp.hasDevice.to!string);
				natpmp_task = Task();
			});

	}
	foreach (t; tasks.data) t.join();
	foreach (string id, Router router; g_routers) {
		if (id !in new_routers) {
			g_registeredMappings.remove(id);
		}
	}
	g_routers = new_routers;
}

shared static ~this() {
	foreach (string router_id, Mapping[] mappings; g_registeredMappings) {
		foreach (mapping; mappings) {
			g_routers[router_id].deleteMapping(mapping.external_port, mapping.is_tcp);
		}
	}
}

shared static this() {
	setTimer(10.seconds, { discover(); }, true);
}

unittest {
	setLogLevel(LogLevel.trace);
	static if (LOG) logInfo("Found devices: %s", getDeviceListing().to!string);

	open(8081, true);
	HTTPServerSettings settings = new HTTPServerSettings();
	settings.port = 8081;
	settings.bindAddresses = ["0.0.0.0"];

	listenHTTP(settings, (scope req, scope res) {
			res.writeBody("OK");
		});
	runTask( { 
			discover();		
		});
	runEventLoop();

	close(8081, true);
}
