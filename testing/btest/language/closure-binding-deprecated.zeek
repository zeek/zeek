# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type mutable_aggregate: record { x: count; };

function reference_capture() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function() { print ++a, --b$x; };
	f();
	++a;
	--b$x;
	f();

	return f;
	}

function reference_capture_double() : function() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function() : function() {
		local c = mutable_aggregate($x=88);
		print ++a;
		local f2 = function() { print a -= 2, --b$x, c$x += 3; };
		c$x = c$x / 2;
		return f2;
		};
	f()();
	++a;
	--b$x;
	f()();

	return f;
	}

event zeek_init()
	{
	print "reference capture";
	local rc = reference_capture();
	rc();

	print "reference double capture";
	local rc2 = reference_capture_double();
	rc2()();
	}
