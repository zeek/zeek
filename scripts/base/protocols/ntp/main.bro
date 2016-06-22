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
    ## The time at the server when the reply was sent
    xmt_time:  time &log &optional;
    ## For stratum 0, 4 character string used for debugging
    kiss_code: string &log &optional;
    ## For stratum 1, ID assigned to the clock by IANA
    ref_id:    string &log &optional;
    ## The IP of the server's reference clock
    ref_clock: addr &log &optional;
	};

	## Event that can be handled to access the NTP record as it is sent on
	## to the logging framework.
	global log_ntp: event(rec: Info);
}

redef record connection += {
	ntp: Info &optional;
};

const ports = { 123/udp };

redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(NTP::LOG, [$columns=Info, $ev=log_ntp, $path="ntp"]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=5
	{
  # Record initialization
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

  # From the request, we get the desired precision
  if ( is_orig )
    {
    info$precision = msg$precision;
    c$ntp = info;
    return;
    }

  # From the response, we fill out most of the rest of the fields.
  info$stratum = msg$stratum;
  info$org_time = msg$org_time;
  info$rec_time = msg$rec_time;
  info$xmt_time = msg$xmt_time;

  # Stratum 1 has the textual reference ID
  if ( msg$stratum == 1 )
     info$ref_id = gsub(msg$ref_id, /\x00*/, "");

  # Higher stratums using IPv4 have the address of the reference server.
  if ( msg$stratum > 1 )
     {
     if ( is_v4_addr(c$id$orig_h) )
          info$ref_clock = msg$ref_addr;
     }
  c$ntp = info;
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
	{
  if ( ! is_orig )
  	{
  	Log::write(NTP::LOG, c$ntp);
  	delete c$ntp;
    }
  }

event connection_state_remove(c: connection) &priority=-5
	{
  if ( c?$ntp )
  	Log::write(NTP::LOG, c$ntp);
	}

event ntp_mode6_message(c: connection, is_orig: bool, opcode: count)
	{
  print "Mode 6", opcode;
	}

event ntp_mode7_message(c: connection, is_orig: bool, opcode: count)
	{
  print "Mode 7", opcode;
	}