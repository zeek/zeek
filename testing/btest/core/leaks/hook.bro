# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local bro -m -b -r $TRACES/wikipedia.trace %INPUT

type rec: record {
	a: count;
	b: string;
};

global myhook: hook(r: rec);
global myhook2: hook(s: string);
# a hook doesn't have to take any arguments
global myhook4: hook();

hook myhook(r: rec) &priority=5
	{
	print "myhook, &priority=5", r;
	# break statement short-circuits the hook handling chain.
	break;
	print "ERROR: break statement should return from hook handler body";
	}

hook myhook(r: rec)
	{
	# This handler shouldn't execute ever because of the handler at priority=5
	# exiting the body from a "break" statement.
	print "myhook, &priority=0", rec;
	}

hook myhook(r: rec) &priority=10
	{
	print "myhook, &priority=10", r;
	# modifications to the record argument will be seen by remaining handlers.
	r$a = 37;
	r$b = "goobye world";
	# returning from the handler early, is fine, remaining handlers still run.
	return;
	print "ERROR: break statement should return from hook handler body";
	}

# hook function doesn't need a declaration, we can go straight to defining
# a handler body.
hook myhook3(i: count)
	{
	print "myhook3", i;
	}

hook myhook4() &priority=1
	{
	print "myhook4", 1;
	}

hook myhook4() &priority=2
	{
	print "myhook4", 2;
	}

event new_connection(c: connection)
	{
	print "new_connection", c$id;

	hook myhook([$a=1156, $b="hello world"]);

	# A hook with no handlers is fine, it's just a no-op.
	hook myhook2("nope");

	hook myhook3(8);
	hook myhook4();

	# A hook can be treated like other data types and doesn't have to be
	# invoked directly by name.
	local h = myhook;
	hook h([$a=2, $b="it works"]);
	}
