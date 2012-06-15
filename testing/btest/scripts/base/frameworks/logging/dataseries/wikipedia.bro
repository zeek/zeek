#
# @TEST-REQUIRES: has-writer DataSeries && which ds2txt
# @TEST-GROUP: dataseries
#
# @TEST-EXEC: bro -r $TRACES/wikipedia.trace Log::default_writer=Log::WRITER_DATASERIES
# @TEST-EXEC: ds2txt --skip-index conn.ds >conn.ds.txt
# @TEST-EXEC: ds2txt --skip-index http.ds >http.ds.txt
# @TEST-EXEC: btest-diff conn.ds.txt
# @TEST-EXEC: btest-diff http.ds.txt
