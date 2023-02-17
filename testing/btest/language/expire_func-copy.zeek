# @TEST-DOC: Test that expire_func is copied (the expiration behavior of existing elements 
#
# @TEST-EXEC: zeek -b -C -r $TRACES/var-services-std-ports.trace %INPUT >output
# @TEST-EXEC: btest-diff output

function inform_me(s: table[string] of count, idx: string): interval
    {
    print fmt("@%.2f expired %s", time_to_double(network_time()), idx);
    return 0secs;
    }

global s: table[string] of count &create_expire=1secs &expire_func=inform_me;
global scopy: table[string] of count;

event new_connection(c: connection)
    {
    s[fmt("%s", c$id)] = 1;
    scopy[fmt("copy %s", c$id)] = 1;
    }

event zeek_init()
	{
	# This copies &expire_func and &create_expire from the value s;
	s["a"] = 5;
	scopy = copy(s);
	scopy["b"] = 5;
	}
