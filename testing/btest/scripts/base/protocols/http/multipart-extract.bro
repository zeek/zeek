# @TEST-EXEC: bro -C -r $TRACES/http/multipart.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: cat http-item-* | sort > extractions

redef HTTP::extract_file_types += /.*/;
