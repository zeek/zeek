# @TEST-DOC: Test that the ASCII writer logs values of type "double" correctly.
#
# @TEST-EXEC: zeek -b %INPUT test-json.zeek
# @TEST-EXEC: mv test.log json.log
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log
# @TEST-EXEC: btest-diff json.log
# 
# Make sure  we do not write out scientific notation for doubles.

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		d: double &log;
	};
}

function logwrite(val: double)
{
	Log::write(Test::LOG, [$d=val]);
}

event zeek_init()
{
	local d: double;
	local dmax: double = 1.79e308;
	local dmin: double = 2.23e-308;

	Log::create_stream(Test::LOG, [$columns=Info]);

	# relatively large values
	logwrite(2153226000.0);
	logwrite(2153226000.1);
	logwrite(2153226000.123456789);

	# relatively small values
	logwrite(1.0);
	logwrite(1.1);
	logwrite(1.123456789);
	logwrite(-1.123456789);
	logwrite(1.1234);
	logwrite(.1234);

	# scientific notation (positive exponents)
	logwrite(5e4);
	logwrite(-5e4);
	logwrite(3.14e15);
	logwrite(-3.14e15);
	logwrite(dmax);
	logwrite(-dmax);

	# scientific notation (negative exponents)
	logwrite(1.23456789e-5);
	logwrite(dmin);
	logwrite(-dmin);

	# inf
	d = dmax;       # ok
	d = d * 2.0;    # inf
	logwrite(d);

	# -inf
	d = -dmax;      # ok
	d = d * 2.0;    # -inf
	logwrite(d);

	# negative zero (compares equal to 0.0, but has different representation)
	d = -0.0;
	logwrite(d);

	# nan
	d = dmax;       # ok
	d = d * 2.0;    # inf
	d = d * 0.0;    # nan
	logwrite(d);
}

# @TEST-START-FILE test-json.zeek

redef LogAscii::use_json = T;

# @TEST-END-FILE
