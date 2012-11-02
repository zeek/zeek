##! Authentication framework for tracking authentication activity
##! in realtime alongside network traffic.

module Auth;

export {
	redef enum Log::ID += { LOG };

	## The authentication endpoint is representative of the
	## host where the login attempted originated from.
	type Endpoint: record {
		## The host that the login originated from.
		host: addr   &log &optional;

		## If the login was over 802.1x then the authentication
		## endpoint is only a mac address.
		mac:  string &log &optional;
	};

	## TODO: account for logouts.
	type Info: record {
		## Timestamp for the login.
		ts:             time     &log;

		## The username seen during the login.
		username:       string   &log;

		## Abstracted endpoint for the authentication originator.
		endpoint:       Endpoint &log;

		## An arbitrary string for the local name given to a 
		## particular service that a user logged into.
		## (e.g. "Corporate VPN" or "Kerberos")
		service:        string   &log;

		## Authentication method; password, key, etc.
		method:         string   &log &optional;

		## Status of the login attempt.
		success:        bool     &log &default=T;

		## The textual reason for the login failure if the 
		## login attempt failed and a reason for the failure 
		## is available.
		failure_reason: string   &log &optional;

		## If the service logged into was something like a VPN that will
		## give the user another IP address, that new IP address will be
		## stored here.
		acquired_host: addr      &log &optional;
	};

	## API events - available through Broccoli or Input framework.
	global login_seen: event(rec: Info);
	#global logout_seen: event(rec: Info);

	## Currently authenticated users are tracked through this variable.
	## The index value is the username.
	global users: table[string] of set[Info];

}

event bro_init() &priority=5
	{
	Log::create_stream(Auth::LOG, [$columns=Info]);
	}


event Auth::login_seen(rec: Info) &priority=-5
	{
	if ( rec$username !in users )
		users[rec$username] = set();

	add users[rec$username][rec];

	Log::write(LOG, rec);
	}

# Old code below

#const unwanted_authentication_countries: set[string] = { "RO", "NG", "A1", "A2" };
#const unwanted_authentication_networks: set[subnet] = {
#41.211.0.0/16,
#41.219.0.0/16,
#41.220.0.0/16,
#41.205.0.0/16,
#62.32.0.0/16,
#80.78.0.0/16,
#80.250.0.0/16,
#80.255.0.0/16,
#81.199.0.0/16,
#82.128.0.0/16,
#83.229.0.0/16,
#196.220.0.0/16,
#196.3.0.0/16,
#196.45.0.0/16,
#};
#
## Table is indexed by username and it's a set of ASNs
#global authentication_asns: table[string] of set[count] &persistent &create_expire=1day;
#
#event bro_init()
#	{
#	#set_buf(auth_log, F);
#	}
#
#redef enum Notice += {
#	Auth_FromUnwantedSource,
#	Auth_TooManySourceASNs,
#};
#
##event authentication(a: auth_info)
#event authentication(username: string, remote_ip: addr, service: string, success: bool, txt: string)
#	{
#	local cc = lookup_location(remote_ip)$country_code;
#	if( success ) 
#		{
#		if (cc in unwanted_authentication_countries || remote_ip in unwanted_authentication_networks)
#			{
#			NOTICE([$note=Auth_FromUnwantedSource,$src=remote_ip,
#		                $msg=fmt("Successful login to %s seen from %s (%s) to %s", username, remote_ip, cc, service)]);
#			}
#
#		local asn = lookup_asn(remote_ip);
#		if ( username !in authentication_asns )
#			authentication_asns[username] = set();
#
#		add authentication_asns[username][asn];
#		if ( |authentication_asns[username]| > 6 )
#			{
#			NOTICE([$note=Auth_TooManySourceASNs, $src=remote_ip,
#			        $msg=fmt("%s logged into from %d ASNs in 24 hours.", username, |authentication_asns[username]|),
#			        $n=|authentication_asns[username]|]);
#			}
#		}	
#
#
#	print auth_log, cat_sep("\t", "\\N",
#                                network_time(), username, remote_ip, service, success, txt);
#	event db_log("authentications", [$epoch=network_time(), $username=username, $remote_ip=remote_ip, $service=service, $success=success, $extended=txt]);
#	}
#
#
#