# This tests that the HTTP analyzer handles HTTP CONNECT proxying correctly
# when the server include a header line into its response.
#
# @TEST-EXEC: zeek -C -r $TRACES/http/connect-with-header.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/tunnels
@load base/frameworks/dpd
