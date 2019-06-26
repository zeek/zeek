#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		data: string &log;
		c: count &log &default=42;
	};
}

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Info]);
	Log::write(Test::LOG, [$data="Test1"]);
	Log::write(Test::LOG, [$data="#Kaputt"]);
	Log::write(Test::LOG, [$data="Test2"]);
}

