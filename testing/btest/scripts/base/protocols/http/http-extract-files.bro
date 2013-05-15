# @TEST-EXEC: bro -C -r $TRACES/web.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff http-item-BFymS6bFgT3-0.dat

redef HTTP::extract_file_types += /text\/html/;
