# This tests for what looks like a problem in the HTTP parser:
# it gets confused whether it's in a header or not; it shouldn't report
# the http_no_crlf_in_header_list wierd.
#
# @TEST-EXEC: zeek -r $TRACES/http/byteranges.trace %INPUT
# @TEST-EXEC: test ! -f weird.log

# The base analysis scripts are loaded by default.
#@load base/protocols/http

