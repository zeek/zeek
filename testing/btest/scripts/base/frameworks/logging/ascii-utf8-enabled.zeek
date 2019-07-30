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
	local a = "foo \xc2\xae bar"; # 2 bytes
	local b = "दुनिया को नमस्ते"; # Hindi characters are 3 byte utf-8
	local c = "hello 𠜎"; # A 4 byte Chinese character

	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::write(Test::LOG, [$s=a]);
	Log::write(Test::LOG, [$s=b]);
	Log::write(Test::LOG, [$s=c]);
}