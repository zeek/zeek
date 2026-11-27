# @TEST-DOC: With HTTP::enable_full_body_file_analysis, a Brotli-compressed multipart body is decompressed in its full body file and matches the same body sent as application/octet-stream.
#
# @TEST-REQUIRES: have-brotli
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-brotli.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid fuid mime_type seen_bytes missing_bytes sha1 files.log

@load base/protocols/http
@load base/files/hash

redef HTTP::enable_full_body_file_analysis = T;

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}
