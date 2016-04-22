module NTP;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:        time    &log;
		## Unique ID for the connection.
		uid:       string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:        conn_id &log;
    ## The version of NTP
		ver:       count &log;
    ## The stratum (primary, secondary, etc.) of the server
    stratum:   count &log &optional;
    ## The precision of the system clock of the client
    precision: interval &log &optional;
    ## The time at the client that the request was sent to the server
    org_time:   time &log &optional;
    ## The time at the server when the request was received
    rec_time:   time &log &optional;
    ## Client's drift
    drift:      interval &log &optional;
    ## The IP of the server's reference clock
    ref_clock: addr &log &optional;
	};

	## Event that can be handled to access the NTP record as it is sent on
	## to the loggin framework.
	global log_ntp: event(rec: Info);
}

redef record connection += {
	ntp: Info &optional;
};

const ports = { 123/udp};

redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(NTP::LOG, [$columns=Info, $ev=log_ntp, $path="ntp"]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
	{
	local info: Info;
  if ( c?$ntp )
  	info = c$ntp;
  else
  	{
	  info$ts  = network_time();
	  info$uid = c$uid;
	  info$id  = c$id;
    info$ver = msg$version;
    }

  if ( is_orig )
    {
    info$precision = msg$precision;
    c$ntp = info;
    return;
    }

  info$stratum = msg$stratum;
  info$org_time = msg$org_time;
  info$rec_time = msg$rec_time;
  info$drift    = msg$rec_time - msg$org_time;
  delete c$ntp;
  Log::write(NTP::LOG, info);
	}