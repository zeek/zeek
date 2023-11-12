# @TEST-DOC: Changing queue parameters while writes are pending.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

@TEST-START-FILE test.zeek
# Used by all tests below.

# Debug printing
global packet_count = 0;

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	post_ts: time &log &optional;
	write_ts: time &log &optional;
	msg: string &log;
};

event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));
	Log::write(LOG, info);
	}


hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "log_policy";
	rec$write_ts = network_time();
	}

event Pcap::file_done(p: string)
	{
	print network_time(), "Pcap::file_done", p;
	}

@TEST-END-FILE test.zeek
# Delay records for a long time, reduce queue size after 10 packets to 3.

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=10sec,
	]);
	}

event new_packet(c: connection, p: pkt_hdr) &priority=-5
	{
	if ( packet_count == 10 )
		{
		print network_time(), "set_max_delay_queue_size to 3";
		Log::set_max_delay_queue_size(LOG, 3);
		}
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	}

# @TEST-START-NEXT
#
# Delay records for a long time, reduce queue size after 10 packets to 3,
# re-delay all records once, provoking failure to free any space in the
# queue.
#
redef record Info += {
	redelayed: bool &default=F;
};

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=10sec,
	]);
	}

function post_delay_cb(rec: Info, id: Log::ID): bool
	{
	if ( ! rec$redelayed )
		{
		print network_time(), "post_delay_cb - re-delay", rec;
		rec$post_ts = network_time();
		rec$redelayed = T;
		Log::delay(id, rec, post_delay_cb);
		return T;
		}


	print network_time(), "post_delay_cb - done", rec;
	return T;
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, post_delay_cb);
	}

event new_packet(c: connection, p: pkt_hdr) &priority=-5
	{
	if ( packet_count == 10 )
		{
		print network_time(), "set_max_delay_queue_size to 3";
		Log::set_max_delay_queue_size(LOG, 3);
		}
	}
