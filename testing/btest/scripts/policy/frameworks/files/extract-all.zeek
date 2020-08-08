# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace frameworks/files/extract-all-files base/protocols/http
# @TEST-EXEC: grep -q EXTRACT files.log
