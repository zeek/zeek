# @TEST-DOC: With HTTP::enable_full_body_file_analysis, the full body reaches file analysis regardless of a message/* or multipart Content-Type. For now, the line-delivered message/* and multipart bodies lose their line endings. Regression test for #1799.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uri resp_fuids resp_mime_types http.log
# @TEST-EXEC: btest-diff-cut -m fuid parent_fuid mime_type seen_bytes missing_bytes sha1 files.log

@load base/protocols/http
@load base/files/extract
@load base/frameworks/notice/weird
@load frameworks/files/hash-all-files

redef HTTP::enable_full_body_file_analysis = T;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( ! is_orig && c?$http && c$http?$resp_body_fuid && f$id == c$http$resp_body_fuid )
		Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
		                    [$extract_filename=fmt("body-%d", c$http$trans_depth)]);
	}
