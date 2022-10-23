##! Implements base functionality for KRB analysis. Generates the kerberos.log
##! file.

@load ./consts
@load base/protocols/conn/removal-hooks

module KRB;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the event happened.
		ts:            time     &log;
		## Unique ID for the connection.
		uid:           string   &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:            conn_id  &log;

		## Request type - Authentication Service ("AS") or
		## Ticket Granting Service ("TGS")
		request_type:  string   &log &optional;
		## Client
		client:        string   &log &optional;
		## Service
		service:       string   &log &optional;

		## Request result
		success:       bool     &log &optional;
		## Error code
		error_code:    count    &optional;
		## Error message
		error_msg:     string   &log &optional;

		## Ticket valid from
		from:          time     &log &optional;
		## Ticket valid till
		till:          time     &log &optional;
		## Ticket encryption type
		cipher:        string   &log &optional;

		## Forwardable ticket requested
		forwardable:   bool     &log &optional;
		## Renewable ticket requested
		renewable:     bool     &log &optional;

		## We've already logged this
		logged:        bool     &default=F;
	};

	## The server response error texts which are *not* logged.
	option ignored_errors: set[string] = {
		# This will significantly increase the noisiness of the log.
		# However, one attack is to iterate over principals, looking
		# for ones that don't require preauth, and then perform
		# an offline attack on that ticket. To detect that attack,
		# log NEEDED_PREAUTH.
		"NEEDED_PREAUTH",
		# This is a more specific version of NEEDED_PREAUTH that's used
		# by Windows AD Kerberos.
		"Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ",
	};

	## Event that can be handled to access the KRB record as it is sent on
	## to the logging framework.
	global log_krb: event(rec: Info);

	## Kerberos finalization hook.  Remaining Kerberos info may get logged when it's called.
	global finalize_krb: Conn::RemovalHook;
}

redef record connection += {
	krb: Info &optional;
};

const tcp_ports = { 88/tcp };
const udp_ports = { 88/udp };
redef likely_server_ports += { tcp_ports, udp_ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB, udp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB_TCP, tcp_ports);
	Log::create_stream(KRB::LOG, [$columns=Info, $ev=log_krb, $path="kerberos", $policy=log_policy]);
	}

function set_session(c: connection): bool
	{
	if ( ! c?$krb )
		{
		c$krb = Info($ts  = network_time(),
		             $uid = c$uid,
		             $id  = c$id);
		Conn::register_removal_hook(c, finalize_krb);
		}

	return c$krb$logged;
	}

function do_log(c: connection)
	{
	if ( c?$krb && ! c$krb$logged )
		{
		Log::write(KRB::LOG, c$krb);
		c$krb$logged = T;
		}
	}

event krb_error(c: connection, msg: Error_Msg) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( msg?$error_text && msg$error_text in ignored_errors )
		{
		if ( c?$krb )
			delete c$krb;

		return;
		}

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		c$krb$client = fmt("%s%s", msg?$client_name ? msg$client_name + "/" : "",
		                           msg?$client_realm ? msg$client_realm : "");

	if ( msg?$service_name )
		c$krb$service    = msg$service_name;

	c$krb$success    = F;
	c$krb$error_code = msg$error_code;

	if ( msg?$error_text )
		c$krb$error_msg = msg$error_text;
	else if ( msg$error_code in error_msg )
		c$krb$error_msg = error_msg[msg$error_code];
	}

event krb_error(c: connection, msg: Error_Msg) &priority=-5
	{
	do_log(c);
	}

event krb_as_request(c: connection, msg: KDC_Request) &priority=5
	{
	if ( set_session(c) )
		return;

	c$krb$request_type = "AS";

	c$krb$client       = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                  msg?$service_realm ? msg$service_realm : "");

	if ( msg?$service_name )
		c$krb$service      = msg$service_name;

	if ( msg?$from )
		c$krb$from = msg$from;
	if ( msg?$till )
		c$krb$till = msg$till;

	if ( msg?$kdc_options )
		{
		c$krb$forwardable = msg$kdc_options$forwardable;
		c$krb$renewable   = msg$kdc_options$renewable;
		}
	}

event krb_as_response(c: connection, msg: KDC_Response) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		{
		c$krb$client = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                msg?$client_realm ? msg$client_realm : "");
		}

	c$krb$service = msg$ticket$service_name;
	c$krb$cipher  = cipher_name[msg$ticket$cipher];
	c$krb$success = T;
	}

event krb_as_response(c: connection, msg: KDC_Response) &priority=-5
	{
	do_log(c);
	}

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options) &priority=5
	{
	if ( set_session(c) )
		return;
	}

event krb_tgs_request(c: connection, msg: KDC_Request) &priority=5
	{
	if ( set_session(c) )
		return;

	c$krb$request_type = "TGS";
	if ( msg?$service_name )
		c$krb$service = msg$service_name;
	if ( msg?$from )
		c$krb$from = msg$from;
	if ( msg?$till )
		c$krb$till = msg$till;

	if ( msg?$kdc_options )
		{
		c$krb$forwardable = msg$kdc_options$forwardable;
		c$krb$renewable   = msg$kdc_options$renewable;
		}
	}

event krb_tgs_response(c: connection, msg: KDC_Response) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		{
		c$krb$client = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                msg?$client_realm ? msg$client_realm : "");
		}

	c$krb$service = msg$ticket$service_name;
	c$krb$cipher  = cipher_name[msg$ticket$cipher];
	c$krb$success = T;
	}

event krb_tgs_response(c: connection, msg: KDC_Response) &priority=-5
	{
	do_log(c);
	}

hook finalize_krb(c: connection)
	{
	do_log(c);
	}
