module NTP;

export {
	redef enum Log::ID += { LOG, CONTROL_LOG, PRIVATE_LOG };

	## Well-known ports for NTP.
	const ports = { 123/udp } &redef;

	global log_policy: Log::PolicyHook;
	global log_policy_control: Log::PolicyHook;
	global log_policy_private: Log::PolicyHook;

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

	## The record type which contains the column fields of the NTP control log.
	type ControlInfo: record {
		## Timestamp for when the event happened.
		ts:         time    &log;
		## Unique ID for the connection.
		uid:        string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:         conn_id &log;
		## The NTP version number (1, 2, 3, 4).
		version:    count   &log;
		## The NTP mode being used.
		mode:       count   &log;
		## The control operation code.
		op_code:    count   &log;
		## The sequence number of the control message.
		sequence:   count   &log;
		## The status word of the control response.
		status:     count   &log;
		## The association ID.
		association_id: count &log;
		## The response bit.  Set to zero for commands, one for responses.
		resp_bit:    bool    &log;
		## The error bit.  Set to zero for normal response, one for error.
		err_bit:     bool    &log;
		## The more bit.  Set to zero for last fragment, one for all others.
		more_bit:    bool    &log;
		## The payload data of the control message.
		data:        string  &log &optional;
		## The key ID used to generate the message-authentication code.
		key_id:      count   &log &optional;
		## The crypto-checksum computed by the encryption procedure.
		crypto_checksum: string &log &optional;
	};

	## The record type which contains the column fields of the NTP private log.
	type PrivateInfo: record {
		## Timestamp for when the event happened.
		ts:         time    &log;
		## Unique ID for the connection.
		uid:        string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:         conn_id &log;
		## The NTP version number (1, 2, 3, 4).
		version:    count   &log;
		## The NTP mode being used.
		mode:       count   &log;
		## The request code.
		req_code:   count   &log;
		## The sequence number of the private message.
		sequence:   count   &log;
		## The implementation number.
		implementation: count &log;
		## The authenticated bit.  If set, this packet is authenticated.
		auth_bit:    bool    &log;
		## The error code.
		err:        count   &log;
		## The payload data of the private message.
		data:       string  &log &optional;
	};

	## Event that can be handled to access the NTP record as it is sent on
	## to the logging framework.
	global log_ntp: event(rec: Info);

	## Event that can be handled to access the NTP control record.
	global log_ntp_control: event(rec: ControlInfo);

	## Event that can be handled to access the NTP private record.
	global log_ntp_private: event(rec: PrivateInfo);
}

redef record connection += {
	ntp:         Info        &optional;
	ntp_control: ControlInfo &optional;
	ntp_private: PrivateInfo &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	Log::create_stream(NTP::LOG, Log::Stream($columns = Info, $ev = log_ntp,
	                    $path="ntp", $policy=log_policy));
	Log::create_stream(NTP::CONTROL_LOG, Log::Stream($columns = ControlInfo,
	                    $ev = log_ntp_control, $path="ntp_control",
	                    $policy=log_policy_control));
	Log::create_stream(NTP::PRIVATE_LOG, Log::Stream($columns = PrivateInfo,
	                    $ev = log_ntp_private, $path="ntp_private",
	                    $policy=log_policy_private));
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=5
	{
	# Mode 1-5: standard NTP synchronization messages.
	if ( msg$mode <= 5 && msg?$std_msg )
		{
		local info: Info;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		info$version = msg$version;
		info$mode = msg$mode;
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

		c$ntp = info;
		}

	# Mode 6: control messages.
	if ( msg?$control_msg )
		{
		local ctrl: ControlInfo;
		ctrl$ts  = network_time();
		ctrl$uid = c$uid;
		ctrl$id  = c$id;
		ctrl$version = msg$version;
		ctrl$mode = msg$mode;
		ctrl$op_code = msg$control_msg$op_code;
		ctrl$sequence = msg$control_msg$sequence;
		ctrl$status = msg$control_msg$status;
		ctrl$association_id = msg$control_msg$association_id;
		ctrl$resp_bit = msg$control_msg$resp_bit;
		ctrl$err_bit = msg$control_msg$err_bit;
		ctrl$more_bit = msg$control_msg$more_bit;
		if ( msg$control_msg?$data )
			ctrl$data = msg$control_msg$data;
		if ( msg$control_msg?$key_id )
			ctrl$key_id = msg$control_msg$key_id;
		if ( msg$control_msg?$crypto_checksum )
			ctrl$crypto_checksum = msg$control_msg$crypto_checksum;

		c$ntp_control = ctrl;
		}

	# Mode 7: private messages.
	if ( msg?$mode7_msg )
		{
		local priv: PrivateInfo;
		priv$ts  = network_time();
		priv$uid = c$uid;
		priv$id  = c$id;
		priv$version = msg$version;
		priv$mode = msg$mode;
		priv$req_code = msg$mode7_msg$req_code;
		priv$sequence = msg$mode7_msg$sequence;
		priv$implementation = msg$mode7_msg$implementation;
		priv$auth_bit = msg$mode7_msg$auth_bit;
		priv$err = msg$mode7_msg$err;
		if ( msg$mode7_msg?$data )
			priv$data = msg$mode7_msg$data;

		c$ntp_private = priv;
		}
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
	{
	if ( c?$ntp )
		Log::write(NTP::LOG, c$ntp);

	if ( c?$ntp_control )
		Log::write(NTP::CONTROL_LOG, c$ntp_control);

	if ( c?$ntp_private )
		Log::write(NTP::PRIVATE_LOG, c$ntp_private);
	}
