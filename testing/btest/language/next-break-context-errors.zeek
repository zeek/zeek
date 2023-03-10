# @TEST-DOC: Check break and next usage within for, while, switch and hooks.

# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
function f()
	{
	next;
	}

event zeek_init() { f(); };

@TEST-START-NEXT
function f()
	{
	break;
	}

event zeek_init() { f(); };

@TEST-START-NEXT
event zeek_init()
	{
	next;
	}

@TEST-START-NEXT
event zeek_init()
	{
	break;
	}

@TEST-START-NEXT
event zeek_init()
	{
	if ( T )
		break;
	}

@TEST-START-NEXT
event zeek_init()
	{
	local history = "Sr";
	switch history {
		case "S":
			print history;
			next;
			break;
	}
	}

@TEST-START-NEXT
global the_hook: hook(c: count);

hook the_hook(c: count)
	{
	next;
	}

@TEST-START-NEXT
global the_hook: hook(c: count);

hook the_hook(c: count)
	{
	if ( T )
		next;
	}

@TEST-START-NEXT
# Should report 3 errors.
global the_hook: hook(c: count);

hook the_hook(c: count)
	{
	next;
	}

event zeek_init()
	{
	break;
	}

event zeek_init()
	{
	next;
	}
