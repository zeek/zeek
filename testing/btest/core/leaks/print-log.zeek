# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

redef Log::print_to_log = Log::REDIRECT_ALL;

event new_connection(c: connection)
    {
    print "hello world ,";
    print 2,T;
    }