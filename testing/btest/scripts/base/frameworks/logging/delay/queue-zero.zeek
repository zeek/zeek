# @TEST-DOC: A zero delay queue limit preserves records until completion or expiration (#5932).
#
# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT >out
# @TEST-EXEC: test ! -s .stderr
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m delay-zero.log

module DelayQueueZero;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		msg: string &log;
	};
}

global tokens: table[string] of Log::DelayToken;
global started = F;
global completed = 0;

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();
	tokens[rec$msg] = Log::delay(id, rec, function[now](delayed_rec: Info, stream_id: Log::ID): bool
		{
		++completed;
		print fmt("complete %s: queue size %d, delay elapsed %s", delayed_rec$msg,
		          Log::get_delay_queue_size(stream_id), network_time() - now >= 1msec);
		return T;
		});
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="delay-zero",
	                        $max_delay_queue_size=0, $max_delay_interval=1msec]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( started )
		return;

	started = T;
	local first = Info($msg="first");

	print fmt("first write: %s", Log::write(LOG, first));
	print fmt("after first write: queue size %d", Log::get_delay_queue_size(LOG));

	print fmt("second write: %s", Log::write(LOG, [$msg="second"]));
	print fmt("after second write: queue size %d", Log::get_delay_queue_size(LOG));
	print fmt("before completion: completed %d", completed);

	print fmt("finish first: %s", Log::delay_finish(LOG, first, tokens["first"]));
	print fmt("after completion: queue size %d", Log::get_delay_queue_size(LOG));

	# Changing a populated queue to unbounded must preserve its existing timer.
	print fmt("set limit 2: %s", Log::set_max_delay_queue_size(LOG, 2));
	print fmt("set limit 0: %s", Log::set_max_delay_queue_size(LOG, 0));
	print fmt("before expiration: queue size %d, completed %d", Log::get_delay_queue_size(LOG), completed);
	}

event Pcap::file_done(path: string)
	{
	# This runs before shutdown drains timers, so expiration must already have happened.
	print fmt("file done: queue size %d, completed %d", Log::get_delay_queue_size(LOG), completed);
	}

event zeek_done()
	{
	print fmt("done: queue size %d", Log::get_delay_queue_size(LOG));
	}
