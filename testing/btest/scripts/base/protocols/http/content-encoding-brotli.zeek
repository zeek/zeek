# @TEST-DOC: Decompress HTTP bodies with Content-Encoding: br. Covers Content-Length, chunked and a corrupted stream. Regression test for #5547.
#
# @TEST-REQUIRES: grep -q "#define USE_BROTLI" $BUILD/zeek-config.h
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-encoding-brotli.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/http

global body_bytes: table[string] of count &default=0;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( ! is_orig )
		body_bytes[c$uid] += length;
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	print "file_sniff", meta?$mime_type ? meta$mime_type : "-", f$bof_buffer[:52];
	}

event zip_analyzer_stats(c: connection, aid: count, total_in: count, total_out: count, exceeded: bool)
	{
	print fmt("zip stats: %s in=%d out=%d exceeded=%s", c$id$orig_p, total_in, total_out, exceeded);
	}

event connection_state_remove(c: connection)
	{
	print fmt("body bytes: %s %d", c$id$orig_p, body_bytes[c$uid]);
	}
