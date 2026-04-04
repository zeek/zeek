# @TEST-DOC: A SSL client hello to a HTTP server responding with HTTP/400 should not generate Protocol_Found or Server_Found notices when using the analyzer/detect-protocols policy script. Regression test for #5204.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tls/ssl-to-http-server.pcap %INPUT >&2
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p trans_depth method host uri version status_code status_msg http.log
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p version cipher curve server_name resumed ssl.log
# @TEST-EXEC: test ! -f notice.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/http

@load policy/frameworks/analyzer/detect-protocols

hook Notice::policy(n: Notice::Info)
	{
	print "unexpected notice generated", n;
	exit(1);
	}
