#
# @TEST-EXEC: bro -b %INPUT 
# @TEST-EXEC: btest-diff test.log

redef LogAscii::empty_field = "EMPTY";

module test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		ss: set[string];
	} &log;
}

event bro_init()
{
	Log::create_stream(test::LOG, [$columns=Log]);

	Log::write(test::LOG, [
		$ss=set("EMPTY")
		]);
}
