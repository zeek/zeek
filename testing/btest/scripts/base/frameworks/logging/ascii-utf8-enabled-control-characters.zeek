#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

redef LogAscii::enable_utf_8 = T;

module Test;
export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}

event zeek_init()
	{
	local a = "foo \n\t\0 bar";
	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::write(Test::LOG, [$s=a]);
	}