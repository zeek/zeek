module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		msg: string &log;
		num: count &log;
	};

	global log_test: event(rec: Test::Info);
}

event bro_init() &priority=5
	{
	Broker::enable();
	Log::create_stream(Test::LOG, [$columns=Test::Info, $ev=log_test, $path="test"]);
	}
