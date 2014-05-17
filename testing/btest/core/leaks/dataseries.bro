# Needs perftools support.
#
# @TEST-REQUIRES: has-writer DataSeries && which ds2txt
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-GROUP: leaks
# @TEST-GROUP: dataseries
#
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -r $TRACES/wikipedia.trace Log::default_writer=Log::WRITER_DATASERIES
# @TEST-EXEC: btest-bg-wait 25
