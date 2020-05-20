# This used to crash the file reassemly code.
#
# @TEST-EXEC: zeek -r $TRACES/http/byteranges.trace frameworks/files/extract-all-files FileExtract::default_limit=4000
# 
# @TEST-EXEC: btest-diff files.log

