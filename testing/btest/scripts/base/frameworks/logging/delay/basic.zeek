# @TEST-DOC: Basic tests.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: touch test.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff-cut -m -F'|' test.log


# @TEST-START-FILE test.zeek
# Used by all tests below.

# Debug printing
global packet_count = 0;
event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	}

event Pcap::file_done(p: string)
	{
	print network_time(), "Pcap::file_done";
	}

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	write_ts: time &log &optional;
	uid: string &log;
	msg: string &log;
};

hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "log_policy", rec$uid;
	rec$write_ts = network_time();
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $policy=log_policy]);
	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $uid=c$uid, $msg="inital-value");
	Log::write(LOG, info);
	}
# @TEST-END-FILE test.zeek


# Delay and immediately release.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec$uid;

	local token = Log::delay(id, rec);
	Log::delay_finish(id, rec, token);
	}

# @TEST-START-NEXT
# Delay and immediately release, twice.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec$uid;

	local token1 = Log::delay(id, rec);
	Log::delay_finish(id, rec, token1);

	local token2 = Log::delay(id, rec);
	Log::delay_finish(id, rec, token2);
	}

# @TEST-START-NEXT
# Delay once, never release.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec$uid;

	Log::delay(id, rec);
	}

# @TEST-START-NEXT
# Delay twice, never release.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec$uid;

	Log::delay(id, rec);
	Log::delay(id, rec);
	}

# @TEST-START-NEXT
# Delay twice, never release, print the token value and its JSON representation.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec$uid;

	local token = Log::delay(id, rec);
	print "token", token;
	print "to_json(token)", to_json(token);
	}
