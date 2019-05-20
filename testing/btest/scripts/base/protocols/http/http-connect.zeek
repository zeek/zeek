# This tests that the HTTP analyzer handles HTTP CONNECT proxying correctly.
#
# @TEST-EXEC: zeek -r $TRACES/http/connect-with-smtp.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff smtp.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/tunnels
@load base/frameworks/dpd
