# This tests that the HTTP analyzer does not generate an unmatched_HTTP_reply
# weird as a result of seeing both a 1xx response and the real response to
# a given request.  The http scripts should also be able log such replies
# in a way that correlates the final response with the request.
#
# @TEST-EXEC: zeek -r $TRACES/http/100-continue.trace %INPUT
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff http.log

# The base analysis scripts are loaded by default.
#@load base/protocols/http

