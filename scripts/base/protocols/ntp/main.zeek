module NTP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the event happened.
		ts:         time	&log;
		## Unique ID for the connection.
		uid:        string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:         conn_id &log;
		## The NTP version number (1, 2, 3, 4).
		version:    count &log;
		## The NTP mode being used.
		mode:       count &log;
		## The stratum (primary server, secondary server, etc.).
		stratum:    count &log;
		## The maximum interval between successive messages.
		poll:       interval &log;
		## The precision of the system clock.
		precision:  interval &log;
		## Total round-trip delay to the reference clock.
		root_delay: interval &log;
		## Total dispersion to the reference clock.
		root_disp:  interval &log;
		## For stratum 0, 4 character string used for debugging.
		## For stratum 1, ID assigned to the reference clock by IANA.
		## Above stratum 1, when using IPv4, the IP address of the reference
		## clock.  Note that the NTP protocol did not originally specify a
		## large enough field to represent IPv6 addresses, so they use
		## the first four bytes of the MD5 hash of the reference clock's
		## IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).
		ref_id:     string &log;
		## Time when the system clock was last set or correct.
		ref_time:   time &log;
		## Time at the client when the request departed for the NTP server.
		org_time:   time &log;
		## Time at the server when the request arrived from the NTP client.
		rec_time:   time &log;
		## Time at the server when the response departed for the NTP client.
		xmt_time:   time &log;
		## Number of extension fields (which are not currently parsed).
		num_exts:   count &default=0 &log;
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

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	Log::create_stream(NTP::LOG, [$columns = Info, $ev = log_ntp, $path="ntp", $policy=log_policy]);
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=5
	{
	local info: Info &is_assigned;	# for case where no $std_msg
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$version = msg$version;
	info$mode = msg$mode;

	if ( msg?$std_msg )
		{
		info$stratum = msg$std_msg$stratum;
		info$poll = msg$std_msg$poll;
		info$precision = msg$std_msg$precision;
		info$root_delay = msg$std_msg$root_delay;
		info$root_disp = msg$std_msg$root_disp;

		if ( msg$std_msg?$kiss_code )
			info$ref_id = msg$std_msg$kiss_code;
		else if ( msg$std_msg?$ref_id )
			info$ref_id = msg$std_msg$ref_id;
		else if ( msg$std_msg?$ref_addr )
			info$ref_id= cat(msg$std_msg$ref_addr);

		info$ref_time = msg$std_msg$ref_time;
		info$org_time = msg$std_msg$org_time;
		info$rec_time = msg$std_msg$rec_time;
		info$xmt_time = msg$std_msg$xmt_time;

		info$num_exts = msg$std_msg$num_exts;
		}

	# Copy the present packet info into the connection record
	# If more ntp packets are sent on the same connection, the newest one
	# will overwrite the previous
	c$ntp = info;
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
	{
	if ( c?$ntp && msg$mode <= 5 )
		Log::write(NTP::LOG, c$ntp);
	}

