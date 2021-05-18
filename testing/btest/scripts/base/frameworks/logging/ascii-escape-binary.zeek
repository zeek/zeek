# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff test.log
# @TEST-EXEC: btest-diff output

redef LogAscii::enable_utf_8 = F;

module Test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}

event zeek_init()
{
	local a = "abc\0def";
	local b = escape_string(a);
	local c = fmt("%s", a);

	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::write(Test::LOG, [$s="AB\0CD\0"]);
	Log::write(Test::LOG, [$s="AB\xffCD\0"]);
	Log::write(Test::LOG, [$s="AB\\xffCD\0"]);
	Log::write(Test::LOG, [$s=" "]);
	Log::write(Test::LOG, [$s=b]);
	Log::write(Test::LOG, [$s=" "]);
	Log::write(Test::LOG, [$s=c]);
	Log::write(Test::LOG, [$s=" "]);
	Log::write(Test::LOG, [$s="foo \xc2\xae bar \\xc2\\xae baz"]);
	Log::write(Test::LOG, [$s="foo\x00bar\\0baz"]);
	Log::write(Test::LOG, [$s="foo \16 bar ^N baz"]);

	print "AB\0CD\0";
	print "AB\xffCD\0";
	print "AB\\xffCD\0";
	print "";
	print b;
	print "";
	print c;
	print "";
	print "foo \xc2\xae bar \\xc2\\xae baz";
	print "foo\x00bar\\0baz";
	print "foo \16 bar ^N baz";

	print "";
}

