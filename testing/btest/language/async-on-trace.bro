# @TEST-EXEC: bro -b -r $TRACES/wikipedia.trace %INPUT 2>&1 | sort >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

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
