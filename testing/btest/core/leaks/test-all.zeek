# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -r $TRACES/wikipedia.trace test-all-policy
# @TEST-EXEC: btest-bg-wait 60
