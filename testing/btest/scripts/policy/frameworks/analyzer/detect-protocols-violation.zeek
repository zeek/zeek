# @TEST-DOC: A HTTP request to a SSH server should not generate Protocol_Found or Server_Found notices when using the analyzer/detect-protocols policy script. Regression test for #5204.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/http/get-to-ssh-server.pcap %INPUT >&2
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h id.resp_p trans_depth method host uri version status_code status_msg http.log
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
