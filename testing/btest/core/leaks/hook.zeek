# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

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
	print "ERROR: return statement should return from hook handler body";
	}

hook myhook(r: rec) &priority=9
	{
	print "myhook return F";
	# return value is ignored, remaining handlers still run, final return
	# value is whether any hook body returned via break statement
	return F;
	print "ERROR: return statement should return from hook handler body";
	}

hook myhook(r: rec) &priority=8
	{
	print "myhook return T";
	# return value is ignored, remaining handlers still run, final return
	# value is whether any hook body returned via break statement
	return T;
	print "ERROR: return statement should return from hook handler body";
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

	print hook myhook([$a=1156, $b="hello world"]);

	# A hook with no handlers is fine, it's just a no-op.
	print hook myhook2("nope");

	print hook myhook3(8);
	print hook myhook4();
	if ( hook myhook4() )
		{
		print "myhook4 all handlers ran";
		}

	# A hook can be treated like other data types and doesn't have to be
	# invoked directly by name.
	local h = myhook;
	print hook h([$a=2, $b="it works"]);
	}
