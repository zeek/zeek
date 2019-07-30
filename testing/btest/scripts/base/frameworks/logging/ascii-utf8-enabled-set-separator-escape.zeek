#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

redef LogAscii::enable_utf_8 = T;

redef LogAscii::set_separator = "\xc2\xae";

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
	Log::write(Test::LOG, [$ss=set("\xc2\xae")]);
	}