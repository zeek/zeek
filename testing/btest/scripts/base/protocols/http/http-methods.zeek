# This tests that the HTTP analyzer handles strange HTTP methods properly.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/methods.trace %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
@load base/frameworks/notice/weird
