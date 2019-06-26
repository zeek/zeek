#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

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
	Log::write(Test::LOG, [$data=double_to_time(1234567890)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.0)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.01)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.001)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.0001)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.00001)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.000001)]);
	Log::write(Test::LOG, [$data=double_to_time(1234567890.0000001)]);
}

