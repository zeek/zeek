#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log
#
# Testing all possible types.

redef LogAscii::use_json = T;


module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

	# Strings taken from https://stackoverflow.com/a/3886015

	# Valid ASCII and valid ASCII control characters
	Log::write(SSH::LOG, [$s="a"]);
	Log::write(SSH::LOG, [$s="\b\f\n\r\t\x00\x15"]);

	# Table 3-7 in https://www.unicode.org/versions/Unicode12.0.0/ch03.pdf describes what is
	# valid and invalid for the tests below

	# Valid 2 Octet Sequence
	Log::write(SSH::LOG, [$s="\xc3\xb1"]);

	# Invalid 2 Octet Sequence
	Log::write(SSH::LOG, [$s="\xc3\x28"]);
	Log::write(SSH::LOG, [$s="\xc0\x81"]);
	Log::write(SSH::LOG, [$s="\xc1\x81"]);
	Log::write(SSH::LOG, [$s="\xc2\xcf"]);

	# Invalid Sequence Identifier
	Log::write(SSH::LOG, [$s="\xa0\xa1"]);

	# Valid 3 Octet Sequence
	Log::write(SSH::LOG, [$s="\xe2\x82\xa1"]);
	Log::write(SSH::LOG, [$s="\xe0\xa3\xa1"]);

	# Invalid 3 Octet Sequence (in 2nd Octet)
	Log::write(SSH::LOG, [$s="\xe0\x80\xa1"]);
	Log::write(SSH::LOG, [$s="\xe2\x28\xa1"]);
	Log::write(SSH::LOG, [$s="\xed\xa0\xa1"]);

	# Invalid 3 Octet Sequence (in 3rd Octet)
	Log::write(SSH::LOG, [$s="\xe2\x82\x28"]);

	# Valid 4 Octet Sequence
	Log::write(SSH::LOG, [$s="\xf0\x90\x8c\xbc"]);
	Log::write(SSH::LOG, [$s="\xf1\x80\x8c\xbc"]);
	Log::write(SSH::LOG, [$s="\xf4\x80\x8c\xbc"]);

	# Invalid 4 Octet Sequence (in 2nd Octet)
	Log::write(SSH::LOG, [$s="\xf0\x80\x8c\xbc"]);
	Log::write(SSH::LOG, [$s="\xf2\x28\x8c\xbc"]);
	Log::write(SSH::LOG, [$s="\xf4\x90\x8c\xbc"]);

	# Invalid 4 Octet Sequence (in 3rd Octet)
	Log::write(SSH::LOG, [$s="\xf0\x90\x28\xbc"]);

	# Invalid 4 Octet Sequence (in 4th Octet)
	Log::write(SSH::LOG, [$s="\xf0\x28\x8c\x28"]);

	# Invalid 4 Octet Sequence (too short)
	Log::write(SSH::LOG, [$s="\xf4\x80\x8c"]);
	Log::write(SSH::LOG, [$s="\xf0"]);
}
