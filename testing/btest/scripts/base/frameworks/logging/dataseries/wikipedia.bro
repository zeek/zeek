#
# @TEST-REQUIRES: has-writer DataSeries && which ds2txt
#
# @TEST-EXEC: bro -r $TRACES/wikipedia.trace Log::default_writer=Log::WRITER_DATASERIES
# @TEST-EXEC: ds2txt conn.ds >conn.ds.txt
# @TEST-EXEC: ds2txt http.ds >http.ds.txt
# @TEST-EXEC: btest-diff conn.ds.txt
# @TEST-EXEC: btest-diff http.ds.txt
