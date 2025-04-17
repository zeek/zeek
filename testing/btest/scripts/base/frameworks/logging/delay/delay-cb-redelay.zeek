# @TEST-DOC: Calling Log::delay() during the post delay callback()
#
# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: touch test.log && zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

redef Log::default_max_delay_interval = 50msec;

# @TEST-START-FILE test.zeek

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

# Delay the given record twice using a nested lambda.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		print network_time(), "post_delay_cb - 1", rec2, delayed_for;

		Log::delay(LOG, rec2, function[now](rec3: Info, id3: Log::ID): bool {
			local delayed_for2 = network_time() - now;
			rec3$msg = fmt("%s delayed %s", rec3$msg, delayed_for2);
			print network_time(), "post_delay_cb - 2", rec3, delayed_for2;
			return T;
		});

		return T;
	});

	when [rec] ( T == F )
		{
		}
	timeout 10msec
		{
		print network_time(), "when timeout", rec;
		}
	}

# @TEST-START-NEXT
# Delay the given record twice using a nested lambda, but also immediate release.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token1 = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		print network_time(), "post_delay_cb - 1, delaying again", rec2, delayed_for;

		local token2 = Log::delay(LOG, rec2, function[now](rec3: Info, id3: Log::ID): bool {
			local delayed_for2 = network_time() - now;
			rec3$msg = fmt("%s delayed %s", rec3$msg, delayed_for2);
			print network_time(), "post_delay_cb - 2", rec3, delayed_for2;
			return T;
		});

		print network_time(), "post_delay_cb - 1, delay_finish", rec2, delayed_for;
		Log::delay_finish(LOG, rec2, token2);

		return T;
	});

	Log::delay_finish(LOG, rec, token1);
	}
