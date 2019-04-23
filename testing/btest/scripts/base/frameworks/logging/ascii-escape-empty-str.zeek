#
# @TEST-EXEC: zeek -b %INPUT 
# @TEST-EXEC: btest-diff test.log

redef LogAscii::empty_field = "EMPTY";

module test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		ss: set[string];
	} &log;
}

event zeek_init()
{
	Log::create_stream(test::LOG, [$columns=Log]);

	Log::write(test::LOG, [
		$ss=set("EMPTY")
		]);
}
