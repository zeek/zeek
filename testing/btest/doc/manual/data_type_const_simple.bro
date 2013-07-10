# @TEST-EXEC: bro -b %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/http

redef HTTP::default_capture_password = T;

