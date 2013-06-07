# @TEST-EXEC: bro -C -r $TRACES/web.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: mv http-item-*.dat http-item.dat
# @TEST-EXEC: btest-diff http-item.dat

redef HTTP::extract_file_types += /text\/html/;
