@load port-name

# Used to annotate apps for connections on ephemeral ports
global conn_app: table[conn_id] of string &default =
	function(id: conn_id): string
		{
		local p = is_icmp_port(id$resp_p) ? id$orig_p : id$resp_p;
		if ( p in port_names )
			return port_names[p];
		else
			return fmt("%s", p);
		};

redef port_names += {
	[0/icmp]	= "icmp-echo",
	[8/icmp]	= "icmp-echo",
	[3/icmp]	= "icmp-unreach",

	[497/tcp]	= "dantz",
	[554/tcp]	= "rtsp",
	[5730/tcp]	= "steltor",	# calendar
	[[7501/tcp, 7502/tcp, 7503/tcp, 7504/tcp, 7505/tcp,
	  7506/tcp, 7507/tcp, 7508/tcp, 7509/tcp, 7510/tcp]]
			= "hpss",
	[[3128/tcp, 8000/tcp, 8080/tcp, 8888/tcp]] = "http",
	[8443/tcp]	= "https",
	[3396/tcp]	= "printer-agent",
	[13782/tcp]	= "veritas-backup-ctrl",
	[16384/tcp]	= "connected-backup",

	[67/udp]	= "dhcp-s",	# bootstrap for diskless hosts
	[68/udp]	= "dhcp-c",	# reply-port
	[427/udp]	= "srvloc",
	[11001/udp]	= "metasys",	# cardkey
	[38293/udp]	= "nav-ping",	# norton anti-virus host discovery
};

