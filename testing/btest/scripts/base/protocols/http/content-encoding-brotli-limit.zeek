# @TEST-DOC: Limit decompressed Brotli HTTP bodies with HTTP::max_uncompressed_size.
#
# @TEST-REQUIRES: grep -q "#define USE_BROTLI" $BUILD/zeek-config.h
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-encoding-brotli.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m uid history conn.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/http

redef HTTP::max_uncompressed_size = 5000;

global body_bytes: table[string] of count &default=0;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( ! is_orig )
		body_bytes[c$uid] += length;
	}

event connection_state_remove(c: connection)
	{
	print fmt("body bytes: %s %d", c$id$orig_p, body_bytes[c$uid]);
	}
