# @TEST-EXEC: zeek -b -Cr $TRACES/http/http-bad-request-with-version.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird
