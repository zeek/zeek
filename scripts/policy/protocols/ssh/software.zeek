##! Extracts SSH client and server information from SSH
##! connections and forwards it to the software framework.

@load base/frameworks/software

module SSH;

export {
	redef enum Software::Type += {
		## Identifier for SSH clients in the software framework.
		SERVER,
		## Identifier for SSH servers in the software framework.
		CLIENT,
	};
}

event ssh_client_version(c: connection, version: string) &priority=4
	{
	# Get rid of the protocol information when passing to the software framework.
	local cleaned_version = sub(version, /^SSH[0-9\.\-]+/, "");
	Software::found(c$id, [$unparsed_version=cleaned_version, $host=c$id$orig_h, $software_type=CLIENT]);
	}

event ssh_server_version(c: connection, version: string) &priority=4
	{
	# Get rid of the protocol information when passing to the software framework.
	local cleaned_version = sub(version, /SSH[0-9\.\-]{2,}/, "");
	Software::found(c$id, [$unparsed_version=cleaned_version, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=SERVER]);
	}
