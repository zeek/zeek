# @TEST-DOC: Verify MIME::max_header_bytes applies to a header's first line.
#
# @TEST-EXEC: zcat <$TRACES/smtp/mime-first-header-size-limit.pcap.gz | zeek -b -r - %INPUT >out
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/smtp
@load base/protocols/conn
@load base/frameworks/notice/weird

redef MIME::max_header_bytes = 1024;

event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( h$name == "SUBJECT" )
		print fmt("%s value bytes: %d", h$name, |h$value|);
	}
