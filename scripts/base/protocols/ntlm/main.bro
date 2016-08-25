@load base/protocols/smb
@load base/frameworks/dpd

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

		## Username given by the client.
		username   : string   &log &optional;
		## Hostname given by the client.
		hostname   : string   &log &optional;
		## Domainname given by the client.
		domainname : string   &log &optional;

		## Indicate whether or not the authentication was successful.
		success    : bool     &log &optional;
		## A string representation of the status code that was 
		## returned in response to the authentication attempt.
		status     : string   &log &optional;

		## Internally used field to indicate if the login attempt 
		## has already been logged.
		done: bool  &default=F;
	};

	## DOS and NT status codes that indicate authentication failure.
	const auth_failure_statuses: set[count] = {
		0x052e0001, # logonfailure
		0x08c00002, # badClient
		0x08c10002, # badLogonTime
		0x08c20002, # passwordExpired
		0xC0000022, # ACCESS_DENIED
		0xC0000061, # PRIVILEGE_NOT_HELD
		0xC000006A, # WRONG_PASSWORD
		0xC000006D, # LOGON_FAILURE
		0xC000006F, # INVALID_LOGON_HOURS
		0xC0000070, # INVALID_WORKSTATION
		0xC0000071, # PASSWORD_EXPIRED
		0xC0000072, # ACCOUNT_DISABLED
	} &redef;
}

redef DPD::ignore_violations += { Analyzer::ANALYZER_NTLM };

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
	if ( c?$ntlm && ! c$ntlm$done )
		{
		if ( c$ntlm?$username || c$ntlm?$hostname )
			{
			Log::write(NTLM::LOG, c$ntlm);
			c$ntlm$done = T;
			}
		}
	}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=3
	{
	if ( c?$ntlm && ! c$ntlm$done &&
	     ( c$ntlm?$username || c$ntlm?$hostname ) )
		{
		c$ntlm$success = (hdr$status !in auth_failure_statuses);
		c$ntlm$status = SMB::statuses[hdr$status]$id;

		Log::write(NTLM::LOG, c$ntlm);
		c$ntlm$done = T;
		}
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=3
	{
	if ( c?$ntlm && ! c$ntlm$done &&
	     ( c$ntlm?$username || c$ntlm?$hostname ) )
		{
		c$ntlm$success = (hdr$status !in auth_failure_statuses);
		c$ntlm$status = SMB::statuses[hdr$status]$id;

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