##! Software identification and extraction for MySQL traffic.

@load base/frameworks/software

module MySQL;

export {
	redef enum Software::Type += {
		## Identifier for MySQL servers in the software framework.
		SERVER,
	};
}

event mysql_server_version(c: connection, ver: string)
	{
	if ( ver == "" )
		return;

	Software::found(c$id, [$unparsed_version=ver, $host=c$id$resp_h, $software_type=SERVER]);
	}
