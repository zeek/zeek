# @TEST-DOC: With HTTP::enable_full_body_file_analysis, chunked transfer coding is removed from multipart bodies, which HTTP doesn't de-chunk itself. The full body files of the chunked responses must match the application/octet-stream control byte for byte, including with chunk extensions, a trailer, leading zeros in chunk sizes, bare LF line endings and gzip content encoding. After a malformed chunk size, which a lenient client may accept, the rest of the body must be forwarded as-is rather than hidden, so it's still recognized as an executable.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-chunked.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid fuid parent_fuid mime_type seen_bytes missing_bytes sha1 files.log
# @TEST-EXEC: cmp extract_files/body-40001 extract_files/body-40002
# @TEST-EXEC: cmp extract_files/body-40001 extract_files/body-40003
# @TEST-EXEC: cmp extract_files/body-40001 extract_files/body-40004

@load base/protocols/http
@load base/files/extract
@load frameworks/files/hash-all-files

redef HTTP::enable_full_body_file_analysis = T;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( ! is_orig && c?$http && c$http?$resp_body_fuid && f$id == c$http$resp_body_fuid )
		Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
		                    [$extract_filename=fmt("body-%d", port_to_count(c$id$orig_p))]);
	}
