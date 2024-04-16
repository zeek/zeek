# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT >out
# @TEST-EXEC: btest-diff out

# Default timer expiration interval is very conservative (10sec) and never runs for short pcaps.
redef table_expire_interval = 0.01sec;

function f(t: table[string] of count, k: string): interval
	{
	print "expire", k, t[k];
	return 0.0sec;
	}

global t: table[string] of count &create_expire=0.1sec &expire_func=f;

# Populate the initial table with two entries.
event zeek_init() &priority=5
	{
	t["a"] = 10;
	t["b"] = 20;
	}

# Replace global t, deleting all entries. In a DEBUG build, table continued
# to exist and its entries spuriously expired over time.
event zeek_init()
	{
	t = table() &create_expire=0.1sec &expire_func=f;
	t["new"] = 42;
	}
