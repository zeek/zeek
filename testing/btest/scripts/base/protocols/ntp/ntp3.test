# @TEST-EXEC: zeek -b -C -r $TRACES/ntp/NTP_sync.pcap %INPUT
# @TEST-EXEC: btest-diff ntp.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ntp

global msg_count = 0;

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
	{
	++msg_count;

	if ( msg_count == 20 || msg_count == 23 )
		{
		# Hack around some unstable floating point output on 32-bit
		local d = interval_to_double(msg$std_msg$root_disp);
		local s = cat(d)[0:-1];
		msg$std_msg$root_disp = double_to_interval(to_double(s));

		d = interval_to_double(msg$std_msg$root_delay);
		s = cat(d)[0:-1];
		msg$std_msg$root_delay = double_to_interval(to_double(s));
		}

	print fmt("ntp_message %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, msg);
	}

