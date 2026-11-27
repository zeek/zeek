# @TEST-DOC: A range request repeated inside a CONNECT tunnel is analyzed by a second HTTP analyzer on the same connection. With HTTP::enable_full_body_file_analysis, each response must still get its own full body file with its own content.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-tunnel.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/protocols/http
@load base/frameworks/analyzer/dpd

redef HTTP::enable_full_body_file_analysis = T;

global body_data: event(f: fa_file, data: string);

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( ! is_orig && c?$http && c$http?$resp_body_fuid && f$id == c$http$resp_body_fuid )
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=body_data]);
	}

event body_data(f: fa_file, data: string)
	{
	if ( |data| > 0 )
		print f$id, data;
	}
