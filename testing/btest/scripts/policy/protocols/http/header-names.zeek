# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
@load protocols/http/header-names
redef HTTP::log_server_header_names=T;
