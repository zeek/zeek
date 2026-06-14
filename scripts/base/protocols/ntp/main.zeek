module NTP;

export {
	redef enum Log::ID += { LOG };

	## Well-known ports for NTP.
	const ports = { 123/udp } &redef;

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
		## The control operation code for a mode 6 message.
		op_code:    count   &log &optional;
		## The sequence number of a mode 6 control message.
		control_sequence: count &log &optional;
		## The status word of a mode 6 control response.
		control_status:   count &log &optional;
		## The association ID of a mode 6 control message.
		association_id:   count &log &optional;
		## The payload data of a mode 6 control message.
		control_data:     string &log &optional;
		## The request code for a mode 7 message.
		req_code:    count  &log &optional;
		## The sequence number of a mode 7 message.
		mode7_sequence: count &log &optional;
		## The implementation number of a mode 7 message.
		mode7_implementation: count &log &optional;
		## The authentication flag for a mode 7 message.
		mode7_auth:  bool   &log &optional;
		## The error code for a mode 7 message.
		mode7_err:   count  &log &optional;
		## The payload data of a mode 7 message.
		mode7_data:  string &log &optional;
	};

	## Event that can be handled to access the NTP record as it is sent on
	## to the logging framework.
	global log_ntp: event(rec: Info);
}

redef record connection += {
	ntp: Info &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	Log::create_stream(NTP::LOG, Log::Stream($columns = Info, $ev = log_ntp, $path="ntp", $policy=log_policy));
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

	if ( msg?$control_msg )
		{
		info$op_code = msg$control_msg$op_code;
		info$control_sequence = msg$control_msg$sequence;
		info$control_status = msg$control_msg$status;
		info$association_id = msg$control_msg$association_id;
		if ( msg$control_msg?$data )
			info$control_data = msg$control_msg$data;
		}

	if ( msg?$mode7_msg )
		{
		info$req_code = msg$mode7_msg$req_code;
		info$mode7_sequence = msg$mode7_msg$sequence;
		info$mode7_implementation = msg$mode7_msg$implementation;
		info$mode7_auth = msg$mode7_msg$auth_bit;
		info$mode7_err = msg$mode7_msg$err;
		if ( msg$mode7_msg?$data )
			info$mode7_data = msg$mode7_msg$data;
		}

	# Copy the present packet info into the connection record
	# If more ntp packets are sent on the same connection, the newest one
	# will overwrite the previous
	c$ntp = info;
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
	{
	if ( c?$ntp )
		Log::write(NTP::LOG, c$ntp);
	}

