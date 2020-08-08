# @TEST-EXEC: zeek -b -C -r $TRACES/ntp/ntp.pcap %INPUT
# @TEST-EXEC: btest-diff ntp.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ntp

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
	{
	print fmt("ntp_message %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, msg);
	}

