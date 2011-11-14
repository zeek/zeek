# @TEST-EXEC: bro -C -r $TRACES/web.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff http-item_141.42.64.125:56730-125.190.109.199:80_resp_1.dat

redef HTTP::extract_file_types += /text\/html/;