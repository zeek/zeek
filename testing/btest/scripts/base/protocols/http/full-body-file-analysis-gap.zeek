# @TEST-DOC: With HTTP::enable_full_body_file_analysis, a gap in a multipart body is reported in its full body file. A gzip-compressed body can't be decompressed past the gap, so its full body file ends there, but must still show missing bytes rather than look complete.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-gap.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid fuid seen_bytes missing_bytes files.log

@load base/protocols/http

redef HTTP::enable_full_body_file_analysis = T;
