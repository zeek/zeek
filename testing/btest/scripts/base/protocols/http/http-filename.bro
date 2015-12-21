# This tests that the filename from the HTTP Content-Disposition header is
# parsed
#
# @TEST-EXEC: bro -r $TRACES/http/http-filename.trace %INPUT
# @TEST-EXEC: btest-diff http.log

# @load base/protocols/http
