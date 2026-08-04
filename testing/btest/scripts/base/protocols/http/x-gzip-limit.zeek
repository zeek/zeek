# @TEST-DOC: Limit decompressed HTTP bodies and report the truncated stream.
#
# @TEST-EXEC: gunzip -c $TRACES/http/gzip-bomb.pcap.gz | zeek -b -r - %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/http

redef ZIP::max_uncompressed_size = 1024 * 1000;

global body_bytes = 0;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( ! is_orig )
		body_bytes += length;
	}

event zeek_done()
	{
	print body_bytes;
	}
