# @TEST-EXEC: bro -r $TRACES/http-pipelined-requests.trace %INPUT > output
# @TEST-EXEC: btest-diff http.log

@load http

redef HTTP::generate_md5 += /image\/png/;