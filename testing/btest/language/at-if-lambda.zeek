# @TEST-DOC: Regression test for #2075 from 0xxon
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stderr

@load base/misc/version

event zeek_init()
	{
	local make_epoch_result = function(pass_name: string): function(ts: time): time
		{
@if ( Version::at_least("4.1") )
		return function [pass_name] (ts: time): time
@else
		return function (ts: time)
@endif
			{
			print pass_name;
			return ts;
			};
		};

	local ts = double_to_time(1660671192.0);
	local f = make_epoch_result("cookie");
	local result = f(ts);
	print type_name(make_epoch_result), type_name(f), type_name(result), result;
	}

@TEST-START-NEXT
# Place braces differently

@load base/misc/version

event zeek_init()
	{
	local make_epoch_result = function(pass_name: string): function(ts: time): time
		{
@if ( Version::at_least("4.1") )
		return function [pass_name] (ts: time): time {
@else
		return function (ts: time) {
@endif
			print pass_name;
			return ts;
			};
		};

	local ts = double_to_time(1660671192.0);
	local f = make_epoch_result("cookie");
	local result = f(ts);
	print type_name(make_epoch_result), type_name(f), type_name(result), result;
	}

@TEST-START-NEXT
# This example doesn't make a whole lot of sense, but adding more @ifdef'ery
# around lambdas.

@load base/misc/version
@load base/utils/numbers

global toggle = F;

event zeek_init()
	{
@if ( toggle )
	local f = function(ts_str: string, offset: count &default=10): time
@else
	local f = function(ts_str: string): time
@endif
		{
		local c = extract_count(ts_str);
@if ( toggle )
		c += offset;
@endif
		return double_to_time(c);
		};

	local result = f("1660671192.0");
	print type_name(f), type_name(result), result;
	}


@TEST-START-NEXT
# Same as above, but toggle T
@load base/utils/numbers

global toggle = T;

event zeek_init()
	{
@if ( toggle )
	local f = function(ts_str: string, offset: count &default=10): time
@else
	local f = function(ts_str: string): time
@endif
		{
		local c = extract_count(ts_str);
@if ( toggle )
		c += offset;
@endif
		return double_to_time(c);
		};

	local result = f("1660671192.0");
	print type_name(f), type_name(result), result;
	}
