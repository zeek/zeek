# This tests that the HTTP analyzer handles HTTP CONNECT proxying correctly.
#
# @TEST-EXEC: bro -r $TRACES/http/connect-with-smtp.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff smtp.log
# @TEST-EXEC: btest-diff tunnel.log

# The base analysis scripts are loaded by default.
#@load base/protocols/http

