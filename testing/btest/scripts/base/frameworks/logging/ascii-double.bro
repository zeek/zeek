#
# @TEST-EXEC: bro -b %INPUT
# @TEST-EXEC: btest-diff test.log
# 
# Make sure  we do not write out scientific notation for doubles.

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		d: double &log;
	};
}

event bro_init()
{
	Log::create_stream(Test::LOG, [$columns=Info]);
	Log::write(Test::LOG, [$d=2153226000.0]);
	Log::write(Test::LOG, [$d=2153226000.1]);
	Log::write(Test::LOG, [$d=2153226000.123456789]);
	Log::write(Test::LOG, [$d=1.0]);
	Log::write(Test::LOG, [$d=1.1]);
	Log::write(Test::LOG, [$d=1.123456789]);
	Log::write(Test::LOG, [$d=1.1234]);
	Log::write(Test::LOG, [$d=3.14e15]);
}

