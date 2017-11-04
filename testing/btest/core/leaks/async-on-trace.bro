# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro -b -m -r $TRACES/wikipedia.trace-b %INPUT
# @TEST-EXEC: btest-bg-wait 60

function f(c: connection)
	{
	local hname = async lookup_addr(c$id$orig_h);
	print "2", c$id$orig_h, hname;
	}

event new_connection(c: connection)
	{
	local hname = async lookup_addr(c$id$resp_h);
	print "2", c$id$resp_h, hname;
	f(c);
	}
