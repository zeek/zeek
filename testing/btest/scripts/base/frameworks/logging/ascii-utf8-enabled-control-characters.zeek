#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff test.log

@load tuning/enable-utf-8-logs

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