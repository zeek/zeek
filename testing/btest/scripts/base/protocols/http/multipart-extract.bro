# @TEST-EXEC: bro -C -r $TRACES/http/multipart.trace %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff http-item-TJdltRTxco1.dat
# @TEST-EXEC: btest-diff http-item-QJO04kPdawk.dat
# @TEST-EXEC: btest-diff http-item-dDH5dHdsRH4.dat
# @TEST-EXEC: btest-diff http-item-TaUJcEIboHh.dat

redef HTTP::extract_file_types += /.*/;
