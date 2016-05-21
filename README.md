# NAT-Opener
## About

Allows anyone to serve a tcp/udp server on specified port behind a router that supports UPNP/NAT-PMP, which should be all of them.

## Usage

You will need to clone https://github.com/etcimon/kxml to use this. Afterwards, using dub, run `dub add-local kxml` on your local copy.

- include nat-opener in your dub project
- discover the routers with `discover()` (this will be done every 10 seconds in case you change wifi 
- ask to open the port using `open(ushort port, bool is_tcp)`
- it will be closed when the application stops, otherwise use the `close` function

Behind the scenes, routers and protocols are resolved and commands are sent to the router to redirect the ports to the running webserver.


## Examples

Look at the `source/natop/opener.d` unittest. 


This is currently beta, make sure you test it out and report any bugs!
