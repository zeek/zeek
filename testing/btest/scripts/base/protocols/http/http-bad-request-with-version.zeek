# @TEST-EXEC: bro -Cr $TRACES/http/http-bad-request-with-version.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

