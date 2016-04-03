module NTLM;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts         : time     &log;
		## Unique ID for the connection.
		uid        : string   &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id         : conn_id  &log;

		username: string &log &optional;
		hostname: string &log &optional;
		domainname: string &log &optional;
	};
}

redef record connection += {
	ntlm: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(NTLM::LOG, [$columns=Info, $path="ntlm"]);
	}

event ntlm_negotiate(c: connection, request: NTLM::Negotiate) &priority=5
	{
	#print request;
	}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge) &priority=5
	{
	#print "challenge!!!!!";
	#print challenge;
	}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) &priority=5
	{
	c$ntlm = NTLM::Info($ts=network_time(), $uid=c$uid, $id=c$id);
	if ( request?$domain_name )
		c$ntlm$domainname = request$domain_name;
	if ( request?$workstation )
		c$ntlm$hostname = request$workstation;
	if ( request?$user_name )
		c$ntlm$username = request$user_name;
	}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) &priority=-5
	{
	Log::write(NTLM::LOG, c$ntlm);
	}
