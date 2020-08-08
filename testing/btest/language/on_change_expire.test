# @TEST-EXEC: zeek -b -C -r $TRACES/var-services-std-ports.trace %INPUT >output
# @TEST-EXEC: btest-diff output

function inform_me(s: table[string] of count, idx: string): interval
    {
    print fmt("expired %s", idx);
    return 0secs;
    }

function change_function(t: table[string] of count, tpe: TableChange, idx: string, val: count)
	{
	print "change_function", idx, val, tpe;
	}

global s: table[string] of count &create_expire=1secs &expire_func=inform_me &on_change=change_function;

event new_connection(c: connection)
    {
    s[fmt("%s", c$id)] = 1;
    }

event zeek_init()
	{
	s["a"] = 5;
	}
