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

function shallow_copy_capture() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[a, b]() { print ++a, --b$x; };
	f();
	++a;
	--b$x;
	f();

	return f;
	}

function deep_copy_capture() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[copy a, copy b]() { print ++a, --b$x; };
	f();
	++a;
	--b$x;
	f();

	return f;
	}

function mixed_copy_capture_a() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[copy a, b]() { print ++a, --b$x; };
	f();
	++a;
	--b$x;
	f();

	return f;
	}

function mixed_copy_capture_b() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[a, copy b]() { print ++a, --b$x; };
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

function shallow_copy_capture_double() : function() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[a,b]() : function() {
		local c = mutable_aggregate($x=88);
		print ++a;
		local f2 = function[a, b, c]() { print a -= 2, --b$x, c$x += 3; };
		c$x = c$x / 2;
		return f2;
		};
	f()();
	++a;
	--b$x;
	f()();

	return f;
	}

function deep_copy1_capture_double() : function() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[copy a, copy b]() : function() {
		local c = mutable_aggregate($x=88);
		print ++a;
		local f2 = function[a, b, c]() { print a -= 2, --b$x, c$x += 3; };
		c$x = c$x / 2;
		return f2;
		};
	f()();
	++a;
	--b$x;
	f()();

	return f;
	}

function deep_copy2_capture_double() : function() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[a, b]() : function() {
		local c = mutable_aggregate($x=88);
		print ++a;
		local f2 = function[copy a, copy b, copy c]()
			{ print a -= 2, --b$x, c$x += 3; };
		c$x = c$x / 2;
		return f2;
		};
	f()();
	++a;
	--b$x;
	f()();

	return f;
	}

function deep_copy3_capture_double() : function() : function()
	{
	local a = 3;
	local b = mutable_aggregate($x=11);
	local f = function[copy a, copy b]() : function() {
		local c = mutable_aggregate($x=88);
		print ++a;
		local f2 = function[copy a, copy b, copy c]()
			{ print a -= 2, --b$x, c$x += 3; };
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
	local rc = reference_capture();
	rc();

	local scc = shallow_copy_capture();
	scc();

	local dcc = deep_copy_capture();
	dcc();

	local mcca = mixed_copy_capture_a();
	mcca();

	local mccb = mixed_copy_capture_b();
	mccb();

	local rc2 = reference_capture_double();
	rc2()();

	local scc2 = shallow_copy_capture_double();
	scc2()();

	local dcc2_1 = deep_copy1_capture_double();
	dcc2_1()();

	local dcc2_2 = deep_copy2_capture_double();
	dcc2_2()();

	local dcc2_3 = deep_copy3_capture_double();
	dcc2_3()();
	}
