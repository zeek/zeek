# @TEST-DOC: The full body of a multipart response must still be found when Zeek flips the connection's roles after attaching the HTTP analyzer. The response's full body file must hold all 77 bytes of the body.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-flip.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m history conn.log
# @TEST-EXEC: btest-diff-cut -m orig_fuids resp_fuids http.log
# @TEST-EXEC: btest-diff-cut -m fuid parent_fuid seen_bytes missing_bytes sha1 files.log

@load base/protocols/conn
@load base/protocols/http
@load frameworks/files/hash-all-files

redef HTTP::enable_full_body_file_analysis = T;
