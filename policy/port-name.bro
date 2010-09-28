const port_names: table[port] of string = {
	[0/icmp] = "icmp-echo",
	[3/icmp] = "icmp-unreach",
	[8/icmp] = "icmp-echo",

	[7/tcp] = "echo",
	[9/tcp] = "discard",
	[20/tcp] = "ftp-data",
	[21/tcp] = "ftp",
	[22/tcp] = "ssh",
	[23/tcp] = "telnet",
	[25/tcp] = "smtp",
	[37/tcp] = "time",
	[43/tcp] = "whois",
	[53/tcp] = "dns",
	[79/tcp] = "finger",
	[80/tcp] = "http",
	[109/tcp] = "pop-2",
	[110/tcp] = "pop-3",
	[111/tcp] = "portmap",
	[113/tcp] = "ident",
	[119/tcp] = "nntp",
	[135/tcp] = "epmapper",
	[139/tcp] = "netbios-ssn",
	[143/tcp] = "imap4",
	[179/tcp] = "bgp",
	[389/tcp] = "ldap",
	[443/tcp] = "https",
	[445/tcp] = "smb",
	[512/tcp] = "exec",
	[513/tcp] = "rlogin",
	[514/tcp] = "shell",
	[515/tcp] = "printer",
	[524/tcp] = "ncp",
	[543/tcp] = "klogin",
	[544/tcp] = "kshell",
	[631/tcp] = "ipp",
	[993/tcp] = "simap",
	[995/tcp] = "spop",
	[1521/tcp] = "oracle-sql",
	[2049/tcp] = "nfs",
	[6000/tcp] = "X11",
	[6001/tcp] = "X11",
	[6667/tcp] = "IRC",

	[53/udp] = "dns",
	[69/udp] = "tftp",
	[111/udp] = "portmap",
	[123/udp] = "ntp",
	[137/udp] = "netbios-ns",
	[138/udp] = "netbios-dgm",
	[161/udp] = "snmp",
	[2049/udp] = "nfs",

} &redef;

function endpoint_id(h: addr, p: port): string
	{
	if ( p in port_names )
		return fmt("%s/%s", h, port_names[p]);
	else
		return fmt("%s/%d", h, p);
	}
