##! Implements base functionality for KRB analysis. Generates the krb.log file.

module KRB;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     			time    &log;
		## Unique ID for the connection.
		uid:    			string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     			conn_id &log;
		## Client
		client:				string &log &optional;
		## Service
		service:			string &log;
		## Ticket valid from
		from:				time &log &optional;
		## Ticket valid till
		till:				time &log &optional;
		## Forwardable ticket requested
		forwardable: 		bool &log &optional;
		## Proxiable ticket requested
		proxiable:			bool &log &optional;
		## Postdated ticket requested
		postdated:			bool &log &optional;
		## Renewable ticket requested
		renewable:			bool &log &optional;
		## The request is for a renewal
		renew_request:		bool &log &optional;
		# The request is to validate a postdated ticket
		validate_request:	bool &log &optional;
		# Network addresses supplied by the client
		network_addrs:		vector of addr &log &optional;
		# NetBIOS addresses supplied by the client
		netbios_addrs:		vector of string &log &optional;
		
		## Result
		result:	string &log &default="unknown";
		## Error code
		error_code: count &log &optional;
		## Error message
		error_msg: string &log &optional;
		## We've already logged this
		logged: bool &default=F;
	};

	## The server response error texts which are *not* logged.
	const ignored_errors: set[string] = {
		# This will significantly increase the noisiness of the log.
		# However, one attack is to iterate over principals, looking
		# for ones that don't require preauth, and then performn
		# an offline attack on that ticket. To detect that attack,
		# log NEEDED_PREAUTH.
		"NEEDED_PREAUTH",
		# This is a more specific version of NEEDED_PREAUTH that's used
		# by Winodws AD Kerberos.
		"Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ",
	} &redef;
	
	## Event that can be handled to access the KRB record as it is sent on
	## to the logging framework.
	global log_krb: event(rec: Info);
}

redef record connection += {
	krb: Info &optional;
};

const udp_ports = { 88/udp, 750/udp };
const tcp_ports = { 88/tcp, 750/tcp };

event bro_init() &priority=5
	{
	Log::create_stream(KRB::LOG, [$columns=Info, $ev=log_krb]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB, udp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB_TCP, tcp_ports);
	}

event krb_error(c: connection, msg: Error_Msg) &priority=5
	{
	local info: Info;

	if ( msg?$error_text && msg$error_text in ignored_errors )
		{
		if ( c?$krb )
			delete c$krb;
		return;
		}

	if ( c?$krb && c$krb$logged )
		return;
		
	if ( c?$krb )
		info = c$krb;
		
	if ( ! info?$ts )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}

	if ( ! info?$client )
		if ( msg?$client_name || msg?$client_realm )
			info$client = fmt("%s%s", msg?$client_name ? msg$client_name + "/" : "",
		  			 	 	  		  msg?$client_realm ? msg$client_realm : "");

	info$service = msg$service_name;
	info$result = "failed";

	info$error_code = msg$error_code;
	
	if ( msg?$error_text )
		info$error_msg = msg$error_text;
	else
		{
		if ( msg$error_code in error_msg )
			info$error_msg = error_msg[msg$error_code];
		}
		
	c$krb = info;
	}

event krb_error(c: connection, msg: Error_Msg) &priority=-5
	{
	Log::write(KRB::LOG, c$krb);
	c$krb$logged = T;
	}

event krb_as_req(c: connection, msg: KDC_Request) &priority=5
	{
	if ( c?$krb && c$krb$logged )
		return;

	local info: Info;

	if ( !c?$krb )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}
	else
		info = c$krb;

	info$client = fmt("%s/%s", msg$client_name, msg$service_realm);
	info$service = msg$service_name;

	if ( msg?$from )
		info$from = msg$from;

	if ( msg?$host_addrs )
		{
		for ( i in msg$host_addrs )
			{
			if ( msg$host_addrs[i]?$ip )
				{
				if ( ! info?$network_addrs )
						info$network_addrs = vector();
				info$network_addrs[|info$network_addrs|] = msg$host_addrs[i]$ip;
				}

			if ( msg$host_addrs[i]?$netbios )
				{
				if ( ! info?$netbios_addrs )
						info$netbios_addrs = vector();
				info$netbios_addrs[|info$netbios_addrs|] = msg$host_addrs[i]$netbios;
				}
			}
		}
		
	info$till = msg$till;
	info$forwardable = msg$kdc_options$forwardable;
	info$proxiable = msg$kdc_options$proxiable;
	info$postdated = msg$kdc_options$postdated;
	info$renewable = msg$kdc_options$renewable;
	
	c$krb = info;
	}

event krb_tgs_req(c: connection, msg: KDC_Request) &priority=5
	{
	if ( c?$krb && c$krb$logged )
		return;

	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$service = msg$service_name;
	if ( msg?$from )
		info$from = msg$from;
	info$till = msg$till;

	c$krb = info;
	}

event krb_as_rep(c: connection, msg: KDC_Reply) &priority=5
	{
	local info: Info;

	if ( c?$krb && c$krb$logged )
		return;

	if ( c?$krb )
		info = c$krb;
		
	if ( ! info?$ts )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}

	if ( ! info?$client )
		info$client = fmt("%s/%s", msg$client_name, msg$client_realm);

	info$service = msg$ticket$service_name;
	info$result = "success";

	c$krb = info;
	}

event krb_as_rep(c: connection, msg: KDC_Reply) &priority=-5
	{
		
	Log::write(KRB::LOG, c$krb);
	c$krb$logged = T;
	}

event krb_tgs_rep(c: connection, msg: KDC_Reply) &priority=5
	{
	local info: Info;

	if ( c?$krb && c$krb$logged )
		return;

	if ( c?$krb )
		info = c$krb;
		
	if ( ! info?$ts )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}

	if ( ! info?$client )
		info$client = fmt("%s/%s", msg$client_name, msg$client_realm);

	info$service = msg$ticket$service_name;
	info$result = "success";
		
	c$krb = info;
	}

event krb_tgs_rep(c: connection, msg: KDC_Reply) &priority=-5
	{
	Log::write(KRB::LOG, c$krb);
	c$krb$logged = T;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$krb && ! c$krb$logged )
		Log::write(KRB::LOG, c$krb);
	}