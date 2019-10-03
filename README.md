tunsocks
--------

tunsocks is a user-level SOCKS, HTTP, and port forwarding proxy for use with
VPNs that typically interact with tun devices. Rather than passing bytes to and
from the tun device, they can pass the data to and from this user-level
program. tunsocks is implemented using lwIP.

Additionally, tunsocks provides connection sharing via NAT.

tunsocks has been tested with OpenConnect:

http://www.infradead.org/openconnect/

Usage
-----

usage: tunsocks <options>

    -L [bind_address:]bind_port:host_address:host_port
    -D [bind_address:]bind_port SOCKS4a/5 proxy
    -H [bind_address:]bind_port HTTP proxy
    -P proxy_pac_file:bind_port HTTP server for proxy.pac
    -R bind_port:host_address:host_port
    -g Allow non-local clients (command line compatibility for ocproxy)
    -k keep alive interval (seconds)
    -m mtu (env INTERNAL_IP4_MTU)
    -s domain_search[,domain_search,...] (env CISCO_DEF_DOMAIN)
    -d dns,[dns,...] (env INTERNAL_IP4_DNS)
    -i ip address (env INTERNAL_IP4_ADDRESS)
    -n netmask
    -G gateway
    -S (Use slirp interface instead VPN, useful for testing)
    -l Add deLay (in ms) to inbound/outbound packets (useful for testing)
    -o DrOp probability ([0.0..1.0]) for inbound/outbound (useful for testing)
    -p pcap_file[:netif] (Default netif 'fd', VPN input)
    -u port (UDP listener port of TAP NAT with no length header, netif=ut)
    -U port (UDP listener port of TAP NAT with 2 byte length header, netif=ut)
    -v VDE path (Connect NAT to a VDE switch. netif=vp)
    -V VDE path (Expose NAT via a reduced functionality VDE switch. netif=vs)
    -t tun name (Expose NAT via a PTP TUN device. netif=tu)
    -T tap name (Expose NAT via a TAP device with DHCP. netif=ta)

Some options also accept input through environmental veriables (see env
above). By default, tunsocks accepts network traffic on stdin, and outputs
network traffic on stdout. The "VPNFD" environmental variable can be used
to pass an alternate fd.

-L [bind_address:]port:host:hostport

	Listen on a local port and optional bind address. When a connection
	is accepted, tunsocks makes a connection on the remote network to
	host:hostport and then pipes the two connections together. If
	host port is not specified, it defaults to port.

-D [bind_address:]port

	Start a SOCKS proxy on a local port and optional bind address. The
	SOCKS proxy supports SOCKS 4, 4A, and 5. The BIND command is
	accepted. If bind_address is not specified, it defaults to
	localhost.

-H [bind_address:]port

	Start a http/https proxy on a local port and optional bind address.

-P proxy_pac_file:port

	Start a http server on localhost at the given port serving up the
	specified proxy PAC file. The server will respond to requests for
	'/', '/proxy.pac', and '/wpad.dat'. The file is re-read each time
	it is requested.

-R port:host:hostport

	tunsocks listens on the specified port on the remote network. When
	a connection is accepted, tunsocks connects to host:hostport on
	the local network and then pipes the two connections together. If
	hostport is not specified, it defaults to port, if host is not
	specified, it defaults to localhost.

-k keep alive interval (seconds)

	TCP keepalive options for all connections on the remote network.

-m mtu (env INTERNAL_IP4_MTU)

	MTU used for the remote network.

-s domain_search[,domain_search,...] (env CISCO_DEF_DOMAIN)

	Domain search order. Follows the same order as resolv.conf(5) search
	with ndots fixed at 1.

-d dns,[dns,...] (env INTERNAL_IP4_DNS)

	DNS servers for the remote network.

-i ip address (env INTERNAL_IP4_ADDRESS)

	IP address to use on the remote network.

-n netmask

	Netmask to use on the remote network.

-g gateway

	IP gateway to use on the remote network.

-S
	Use slirp interface instead VPN for outbound connection. This uses
	the host's IP stack to make outbound connections.

-l delay_ms

	Add a delay (in ms) to inbound/outbound packets (useful for testing).

-o probability

	Set a probability for dropping packets for inbound/outbound (useful
	for testing).

-p pcap_file[:netif]

	If specified, all traffic is saved to the specified file in pcap
	format. The default interface is 'fd', which is the VPN interface.

-u port

	Provides a NAT connection to the VPN via raw packets. The network
	provides a DHCP server that assigns clients an IP address, subnet,
	default route, DNS server, and domain names appropriately. The network
	is 10.0.4.0/24.

	tunsocks will listen for raw Ethernet packets on the given UDP port.
	Whenever it receives a packet, it will associated the sender's hardware
	address with the sender's IP and port. Any packets destined for the
	sender's IP address will be returned. Any packets destined for the
	broadcast address will be sent to all current clients.

	The netif name for use with -p i- 'ut'.

-U port

	Like -u, but all packets include a 2 byte big-endian length header.

-v VDE path

	Like -u, but connects to the given VDE switch. The network is
	10.0.5.0/24. The netif name is 'vp'.

-V VDE path

	Like -u, but emulates a VDE switch. The network is 10.0.6.0/24. The
	netif name is 'vs'.

-T tap name

	Like -u but sends and receives packets via a supplied TAP device. The
	network is 10.0.7.0/24. The netif name is 'ta'.

-t tun name

	Like -T but operates with TUN devices at the IP layer. This operates
	as a point-to-point interface and does not supply a DHCP server. The
	client must correctly configure IP and DNS settings. The IP address
	of the point-to-point device is 10.0.8.1. The netif name is 'tu'.

Examples
--------

	openconnect --script-tun --script "tunsocks -D 8080 -R ssh \
		-L 8888:webproxy.example.com:80" vpn.example.com

tunsocks is configured to start a SOCKS server on localhost at port 8080.
SSH connections on the remote network to our given IP address will connect
to our local SSH server. A HTTP proxy is available on the remote network
for accessing specific hosts, it is accessible via localhost:8888.
Openconnect sets the other necessary parameters via environmental variables.


tsocks configuration
--------------------

tsocks can easily wrap applications via an LD_PRELOAD so that network
requests instead travel via a proxy.

/etc/tsocks.conf:
server = 127.0.0.1
server_type = 5
server_port = 8080

tsocks nc 10.15.12.12 55


git configuration using socat
-----------------------------

This configures git to use the localhost:8080 SOCKS proxy for connection
to git.example.com.

~/.gitconfig:
[core]
	gitproxy=/home/joeuser/bin/git-proxy-wrapper for git.example.com

~/bin/git-proxy-wrapper:
exec socat STDIO SOCKS4A:localhost:$1:$2,socksport=8080


ssh configuration using socat
-----------------------------

This utilizes the localhost:8080 SOCKS proxy for any ssh connections in the
*.intranet.example.com domain

~/.ssh/config:
Host *.intranet.example.com
ProxyCommand socat - SOCKS4A:localhost:%h:%p,socksport=8080


Web browser and general desktop application configuration
---------------------------------------------------------

Although web browsers and general desktop applications can be configured
to use a single proxy easily, it is much more convenient to utilize a
proxy.pac file. A proxy.pac file allows sets of rules for determining which
connections should utilize the proxy.

function FindProxyForURL(url, host) {

	// This rule allows single word domain names, such as "time" to
	// resolve via the VPN. This is common on corporate intranets.
	// tunsocks utilizes the domain search list in this case
	if (isPlainHostName(host))
		return "SOCKS5 127.0.0.1:8080";

	// proxy.pac can be used to easily funnel entire domains
	if (dnsDomainIs(host, ".intranet.example.com") ||
	    dnsDomainIs(host, ".documents.example.com"))
		return "SOCKS5 127.0.0.1:8080";

	// Or single hosts
	if (host == "passwords.example.com" || host == "10.55.22.55")
		return "SOCKS5 127.0.0.1:8080";

	// This is a slightly more complex example where certain hosts on the
	// intranet are only accessible by going through a web proxy available
	// via the VPN. A rule '-L 8888:webproxy.example.com:80' is added to
	// the tunsocks command line options. The following proxy.pac rule then
	// forwards requests for the given domain to that webproxy
	if (dnsDomainIs(host, "*.local.example.com"))
		return "PROXY localhost:8888";

	// Everything else should access the Internet directly, without the
	// VPN
	return "DIRECT";
}

proxy.pac files can support a wide variety of configurations, even multiplexing
between multiple VPN connections. A proxy.pac file is generally assigned under
the application or system proxy configuration page by selecting 'Automatic'
and then using 'file:///path/to/proxy.pac' in the 'Configuration URL' field.

Use of NAT with QEMU
--------------------

Multiple methods can be used with QEMU, but the simplest is the UDP interface:

For QEMU:

-nic socket,udp=127.0.0.1:22222,localaddr=127.0.0.1:22223,mac=52:54:00:12:34:56

For tunsocks:

-u 22222

Note that different instances of QEMU should supply different localaddr ports.

Use of NAT with Vagrant
-----------------------

Using the NAT interface with Vagrant is a little more complex as Vagrant
requires a working interface to the host for ssh access:

    vb.customize ["modifyvm", :id, "--nic1", "generic"]
    vb.customize ["modifyvm", :id, "--nicgenericdrv1", "UDPTunnel"]
    vb.customize ["modifyvm", :id, "--nicproperty1", "dest=127.0.0.1"]
    vb.customize ["modifyvm", :id, "--nicproperty1", "dport=22222"]

    vb.customize ["modifyvm", :id, "--nic2", "nat"]
    vb.customize ["modifyvm", :id, "--natpf2", "ssh,tcp,127.0.0.1,2222,,22"]

The above sets up two interfaces, one for the primary connection that uses
the UDP NAT interface of tunsocks, and a second interface for ssh access.

Compile
-------

Compiling tunsocks is fairly easy one. You need to clone and initialize its git modules using following commands

    git clone https://github.com/russdill/tunsocks
    git submodule init
    git submodule update

Then you need to make sure all prerequisites are installed

- `libevent`
- `autotools`
- `make`

For compiling the code you just need to run:

    ./autogen.sh
    ./configure
    make

Credits
-------

tunsocks was written by Russ Dill <russ.dill@gmail.com> with inspiration from
ocproxy by David Edmondson <dme@dme.org> and Kevin Cernekee <cernekee@gmail.com>

License
-------

tunsocks is complied into and licensed under the same license as lwIP. For
a copy of the license, see lwip/COPYING.
