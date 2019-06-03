# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff http.log

@load protocols/http/header-names
redef HTTP::log_server_header_names=T;
