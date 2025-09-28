# @TEST-DOC: Test some redeclaration, redefinition errors.

# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global x = 1;
global x = 2;

# @TEST-START-NEXT

global f: function() = function() { };
global f: function() = function() { };

# @TEST-START-NEXT

global f: function();
global f: function();

# @TEST-START-NEXT

event zeek_init()
	{
	local f = function() { };
	local f = function() { };
	}

# @TEST-START-NEXT
event zeek_init()
	{
	local f: function();
	local f: function();
	}

# @TEST-START-NEXT
event zeek_init()
	{
	local x = 1;
	local x = 2;
	}

# @TEST-START-NEXT
global ev: event();
global ev: event();

# @TEST-START-NEXT
global ev: event(x: bool, y: count);
global ev: event(x: bool, y: count);

# @TEST-START-NEXT
global ev: event(x: bool);
global ev: event(xx: bool);

# @TEST-START-NEXT
global f: event();
global f: hook();
global f: function();

# @TEST-START-NEXT
global f = function() { };
global f: hook();
global f: event();

# @TEST-START-NEXT
global f = function() { };
type f: bool;

# @TEST-START-NEXT
type f: record {};
type f: bool;
