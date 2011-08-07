#
# @TEST-EXEC: BRO_NO_BASE_SCRIPTS=1 bro %INPUT
# @TEST-EXEC: btest-diff test.log

module Test;

export {
	redef enum Log::ID += { TEST };

	type Info: record {
		data: time &log;
	};
}

event bro_init()
{
	Log::create_stream(TEST, [$columns=Info]);
	Log::write(TEST, [$data=double_to_time(1234567890)]);
	Log::write(TEST, [$data=double_to_time(1234567890.0)]);
	Log::write(TEST, [$data=double_to_time(1234567890.01)]);
	Log::write(TEST, [$data=double_to_time(1234567890.001)]);
	Log::write(TEST, [$data=double_to_time(1234567890.0001)]);
	Log::write(TEST, [$data=double_to_time(1234567890.00001)]);
	Log::write(TEST, [$data=double_to_time(1234567890.000001)]);
	Log::write(TEST, [$data=double_to_time(1234567890.0000001)]);
}

