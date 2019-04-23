# This tests that the HTTP analyzer handles strange HTTP methods properly.
#
# @TEST-EXEC: zeek -r $TRACES/http/methods.trace %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff http.log

# The base analysis scripts are loaded by default.
#@load base/protocols/http

