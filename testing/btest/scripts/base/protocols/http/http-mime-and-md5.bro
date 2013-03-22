# This tests md5 calculation for a specified mime type.

# @TEST-EXEC: bro -r $TRACES/http/pipelined-requests.trace %INPUT > output
# @TEST-EXEC: btest-diff http.log

redef HTTP::generate_md5 += /image\/png/;
