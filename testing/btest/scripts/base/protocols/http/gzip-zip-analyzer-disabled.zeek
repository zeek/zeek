# @TEST-DOC: HTTP passes a gzip body through as is when the ZIP analyzer is disabled.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/get-gzip.pcap base/protocols/http %INPUT >enabled.out
# @TEST-EXEC: zeek -b -r $TRACES/http/get-gzip.pcap base/protocols/http %INPUT disable=T >disabled.out
# @TEST-EXEC: btest-diff enabled.out
# @TEST-EXEC: btest-diff disabled.out

option disable = F;

event zeek_init()
	{
	if ( disable )
		Analyzer::disable_analyzer(Analyzer::ANALYZER_ZIP);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( ! is_orig )
		print length, bytestring_to_hexstr(data[:4]);
	}

event zip_analyzer_stats(c: connection, aid: count, total_in: count, total_out: count, exceeded: bool)
	{
	print fmt("zip stats: in=%d out=%d", total_in, total_out);
	}
