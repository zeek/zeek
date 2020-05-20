# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

module Test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		ss: set[string];
	} &log;
}

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);


	Log::write(Test::LOG, [$ss=set("AA", ",", ",,", "CC")]);
}

