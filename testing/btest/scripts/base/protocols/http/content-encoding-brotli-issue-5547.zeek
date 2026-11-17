# @TEST-DOC: Decompress the Brotli bodies from the trace attached to #5547 (Content-Length and chunked).
#
# @TEST-REQUIRES: grep -q "#define USE_BROTLI" $BUILD/zeek-config.h
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-encoding-brotli-issue-5547.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/http

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	print f$bof_buffer;
	}
