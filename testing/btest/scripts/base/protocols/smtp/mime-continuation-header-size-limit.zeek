# @TEST-DOC: Verify MIME::max_header_bytes applies to a header continuation line.
#
# @TEST-EXEC: zcat <$TRACES/smtp/mime-continuation-header-size-limit.pcap.gz | zeek -b -r - %INPUT >out
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/smtp
@load base/protocols/conn
@load base/frameworks/notice/weird

redef MIME::max_header_bytes = 1024;
redef Log::default_max_field_string_bytes = 0;
redef Log::default_max_total_string_bytes = 0;

event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( h$name == "SUBJECT" )
		print fmt("%s value bytes: %d", h$name, |h$value|);
	}
