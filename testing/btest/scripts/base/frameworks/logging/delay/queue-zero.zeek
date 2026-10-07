# @TEST-DOC: A zero-sized delay queue evicts every record without crashing (#5932).
#
# @TEST-EXEC: zeek -b %INPUT >out
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

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	Log::delay(id, rec, function(delayed_rec: Info, stream_id: Log::ID): bool
		{
		print fmt("evict %s: queue size %d", delayed_rec$msg, Log::get_delay_queue_size(stream_id));
		return T;
		});
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="delay-zero", $max_delay_queue_size=0]);

	print fmt("first write: %s", Log::write(LOG, [$msg="first"]));
	print fmt("after first write: queue size %d", Log::get_delay_queue_size(LOG));

	# A second eviction also verifies that the evicting flag was reset.
	print fmt("second write: %s", Log::write(LOG, [$msg="second"]));
	print fmt("after second write: queue size %d", Log::get_delay_queue_size(LOG));
	}

event zeek_done()
	{
	print fmt("done: queue size %d", Log::get_delay_queue_size(LOG));
	}
