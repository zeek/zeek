# Authorization: Basic is followed by two spaces rather than one.
#
# @TEST-EXEC: zeek -b -Cr $TRACES/http/basic-auth-with-extra-space.trace %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http

redef HTTP::default_capture_password = T;
