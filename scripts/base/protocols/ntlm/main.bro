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

		## Indicate whether or not the authentication was successful.
		success: bool &log &optional;

		## Internally used field to indicate if the login attempt 
		## has already been logged.
		done: bool &default=F;
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
	}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge) &priority=5
	{
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

event gssapi_neg_result(c: connection, state: count) &priority=3
	{
	if ( c?$ntlm )
		c$ntlm$success = (state == 0);
	}

event gssapi_neg_result(c: connection, state: count) &priority=-3
	{
	if ( c?$ntlm )
		{
		if ( c$ntlm?$username || c$ntlm?$hostname )
			{
			Log::write(NTLM::LOG, c$ntlm);
			c$ntlm$done = T;
			}
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=3
	{
	if ( c?$ntlm &&
	     ( c$ntlm?$username || c$ntlm?$hostname ) &&
	     hdr$status == 0xC000006D )
		{
		c$ntlm$success = F;
		Log::write(NTLM::LOG, c$ntlm);
		c$ntlm$done = T;
		}
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$ntlm && ! c$ntlm$done )
		{
		Log::write(NTLM::LOG, c$ntlm);
		}
	}