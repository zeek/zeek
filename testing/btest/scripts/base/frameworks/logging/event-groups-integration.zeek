# @TEST-DOC: Count packets, disable the packet log stream (and it's module group) and re-enable it again, verifying handlers are disabled and re-enabled, too.

# @TEST-EXEC: zeek -b -r ${TRACES}/wikipedia.trace -f 'port 53' %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff packet.log

module PacketCounter;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		c: count &log;
		ttl: count &log;
		len: count &log;
	};

	# Counting all the packets.
	global pcount = 0;
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="packet",
	                         $event_groups=set("PacketCounter::Logging")]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	++pcount;

	print "packet counting", pcount;

	# Have 5 packets logged, now disable the stream.
	if ( pcount == 6 )
		{
		print "Log::disable_stream()";
		Log::disable_stream(LOG);
		}

	# Re-enable logging after 25 packets. Packet 25 will actually
	# be logged as the handler is enabled just before this one
	# (at a higher priority) completes.
	if ( pcount == 25 )
		{
		print "Log::enable_stream()";
		Log::enable_stream(LOG);
		}
	}

# Handler with a attribute group matching the log stream event group.
# It only produces a bit of output to verify it's being disabled and
# re-enabled during Log::enable_stream() / Log::disable_stream().
event new_packet(c: connection, p: pkt_hdr) &group="PacketCounter::Logging" &priority=-5
	{
	print "packet observer", pcount;
	}

# This is where our actual logging happens. We have a "print" statement
# as to verify the code doesn't actually run when the stream got disabled.
module PacketCounter::Logging;

event new_packet(c: connection, p: pkt_hdr) &priority=-10
	{
	print "packet logging", PacketCounter::pcount;
	local rec = PacketCounter::Info(
		$ts=network_time(),
		$c=PacketCounter::pcount,
		$ttl=p$ip$ttl,
		$len=p$ip$len,
	);

	Log::write(PacketCounter::LOG, rec);
	}
