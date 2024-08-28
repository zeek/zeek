# Authorization: Basic password has a colon in its value
#
# @TEST-EXEC: zeek -b -r $TRACES/http/basic-auth-with-colon.trace %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http

redef HTTP::default_capture_password = T;
