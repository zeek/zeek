#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-openclose-timestamps btest-diff test.log

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		data: time &log;
	};
}

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Info]);
	Log::write(Test::LOG, [$data=1234567890 as time]);
	Log::write(Test::LOG, [$data=1234567890.0 as time]);
	Log::write(Test::LOG, [$data=1234567890.01 as time]);
	Log::write(Test::LOG, [$data=1234567890.001 as time]);
	Log::write(Test::LOG, [$data=1234567890.0001 as time]);
	Log::write(Test::LOG, [$data=1234567890.00001 as time]);
	Log::write(Test::LOG, [$data=1234567890.000001 as time]);
	Log::write(Test::LOG, [$data=1234567890.0000001 as time]);
	Log::write(Test::LOG, [$data=2385642157 as time]);
}

