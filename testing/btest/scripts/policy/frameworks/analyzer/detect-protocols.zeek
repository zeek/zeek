# @TEST-DOC: Test notices generated for a HTTP server running on port 22/tcp.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/http/http-single-conn-22.pcap %INPUT >&2
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p note msg sub src dst p n notice.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/http

@load policy/frameworks/analyzer/detect-protocols
