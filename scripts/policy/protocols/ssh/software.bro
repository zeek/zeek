
module SSH;

export {
	redef enum Software::Type += {
		SERVER,
		CLIENT,
	};
}

event ssh_client_version(c: connection, version: string) &priority=4
	{
	# Get rid of the protocol information when passing to the software framework.
	local cleaned_version = sub(version, /^SSH[0-9\.\-]+/, "");
	local si = Software::parse(cleaned_version, c$id$orig_h, CLIENT);
	Software::found(c$id, si);
	}

event ssh_server_version(c: connection, version: string) &priority=4
	{
	# Get rid of the protocol information when passing to the software framework.
	local cleaned_version = sub(version, /SSH[0-9\.\-]{2,}/, "");
	local si = Software::parse(cleaned_version, c$id$resp_h, SERVER);
	Software::found(c$id, si);
	}
