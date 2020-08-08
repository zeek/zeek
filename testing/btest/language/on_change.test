# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

module TestModule;

function change_function(t: table[string, int] of count, tpe: TableChange, idxa: string, idxb: int, val: count)
	{
	print "change_function", idxa, idxb, val, tpe;
	}

function set_change(t: set[string], tpe: TableChange, idx: string)
	{
	print "set_change", idx, tpe;
	}

global t: table[string, int] of count &on_change=change_function;
global s: set[string] &on_change=set_change;

event zeek_init()
	{
	print "inserting";
	t["a", 1] = 5;
	add s["hi"];
	print "changing";
	t["a", 1] = 2;
	print "deleting";
	delete t["a", 1];
	delete s["hi"];
	}
