# @TEST-DOC: Limit decompressed IRC server-to-server links and report the truncated stream.
#
# @TEST-EXEC: zeek -b -r $TRACES/irc-zip-bomb.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/irc
@load base/misc/zip-analyzer-limit

redef IRC::max_uncompressed_size = 1024 * 1000;

global msg_count = 0;

event irc_message(c: connection, is_orig: bool, prefix: string, command: string,
    message: string)
	{
	if ( ! is_orig )
		++msg_count;
	}

event zip_analyzer_stats(c: connection, aid: count, total_in: count, total_out: count, exceeded: bool)
	{
	print fmt("zip stats: in=%d out=%d exceeded=%s", total_in, total_out, exceeded);
	}

event zeek_done()
	{
	print msg_count;
	}
