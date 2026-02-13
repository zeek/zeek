# @TEST-DOC: Test for non-printable bytes (control and non-UTF8 bytes with high bits set) from #3948
#
# @TEST-REQUIRES: which jq
#
# @TEST-EXEC: zeek -b %INPUT LogAscii::use_json=T
# @TEST-EXEC: btest-diff escape.log
# Ensure jq can deal with, but do not baseline it because it'll
# fiddle with UTF-8 / Unicode and that might be confusing.
# @TEST-EXEC: jq -a < escape.log > /dev/null

module Escape;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		my_str: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(Escape::LOG, [$columns=Escape::Info, $path="escape"]);

	Log::write(Escape::LOG, [$my_str="byte 00: \x00"]);
	Log::write(Escape::LOG, [$my_str="byte 00 escaped: \\x00"]);

	Log::write(Escape::LOG, [$my_str="byte 07: \x07"]);
	Log::write(Escape::LOG, [$my_str="byte 07 escaped: \\x07"]);

	Log::write(Escape::LOG, [$my_str="byte D4: \xd4"]);
	Log::write(Escape::LOG, [$my_str="byte D4 escaped: \\xd4"]);

	Log::write(Escape::LOG, [$my_str="a tab: \t"]);
	Log::write(Escape::LOG, [$my_str="a newline: \n"]);
	Log::write(Escape::LOG, [$my_str="quotes: \"hooray\""]);
	Log::write(Escape::LOG, [$my_str="mix: \"a newline \n in quotes\" followd by a zero byte \"\x00\" also in quotes"]);
	Log::write(Escape::LOG, [$my_str="the slash / needs no escaping, so /\x01/ is /u0001/ with an extra backslash"]);

	Log::write(Escape::LOG, [$my_str="a rocket: \xf0\x9f\x9a\x80"]);

	# Ensure \xc3\x94 is not converted to \u00d4
	Log::write(Escape::LOG, [$my_str="unicode char D4 in utf-8: \xc3\x94 and a rocket: \xf0\x9f\x9a\x80"]);

	Log::write(Escape::LOG, [$my_str="byte 07: \x07 and unicode char D4 in utf-8: \xc3\x94 and a rocket: \xf0\x9f\x9a\x80"]);
	Log::write(Escape::LOG, [$my_str="byte D4: \xd4 unicode char D4 in utf-8: \xc3\x94 and a rocket: \xf0\x9f\x9a\x80"]);
	Log::write(Escape::LOG, [$my_str="byte 07: \x07 and byte D4: \xd4 unicode char D4 in utf-8: \xc3\x94 and a rocket: \xf0\x9f\x9a\x80"]);
	Log::write(Escape::LOG, [$my_str="byte 07: \x07 and byte D4: \xd4 unicode char D4 in utf-8: \xc3\x94 and another 07 byte: \x07 and a rocket \xf0\x9f\x9a\x80"]);
    }
