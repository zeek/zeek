# This used to crash the file reassemly code.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/byteranges.trace base/protocols/http base/files/hash frameworks/files/extract-all-files FileExtract::default_limit=4000
# 
# @TEST-EXEC: btest-diff files.log

