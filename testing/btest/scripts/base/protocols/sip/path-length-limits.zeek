# @TEST-DOC: Verify repeated SIP Via headers do not grow one transaction path without bound.
#
# @TEST-EXEC: zeek -b -r $TRACES/sip/sip-long-request-response-paths.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
@load base/protocols/sip

redef SIP::max_request_path_length = 3;
redef SIP::max_response_path_length = 7;

event SIP::log_sip(rec: SIP::Info)
	{
	if ( rec?$request_path && |rec$request_path| > 1 )
		print fmt("request_path_len=%d", |rec$request_path|);

	if ( rec?$response_path && |rec$response_path| > 1 )
		print fmt("response_path_len=%d", |rec$response_path|);

	}
