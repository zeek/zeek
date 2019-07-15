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

	# Valid 2 Octet Sequence
	Log::write(SSH::LOG, [$s="\xc3\xb1"]);
	
	# Invalid 2 Octet Sequence
	Log::write(SSH::LOG, [$s="\xc3\x28"]);
	
	# Invalid Sequence Identifier
	Log::write(SSH::LOG, [$s="\xa0\xa1"]);
	
	# Valid 3 Octet Sequence
	Log::write(SSH::LOG, [$s="\xe2\x82\xa1"]);
	
	# Invalid 3 Octet Sequence (in 2nd Octet)
	Log::write(SSH::LOG, [$s="\xe2\x28\xa1"]);
	
	# Invalid 3 Octet Sequence (in 3rd Octet)
	Log::write(SSH::LOG, [$s="\xe2\x82\x28"]);
	
	# Valid 4 Octet Sequence
	Log::write(SSH::LOG, [$s="\xf0\x90\x8c\xbc"]);
	
	# Invalid 4 Octet Sequence (in 2nd Octet)
	Log::write(SSH::LOG, [$s="\xf0\x28\x8c\xbc"]);
	
	# Invalid 4 Octet Sequence (in 3rd Octet)
	Log::write(SSH::LOG, [$s="\xf0\x90\x28\xbc"]);
	
	# Invalid 4 Octet Sequence (in 4th Octet)
	Log::write(SSH::LOG, [$s="\xf0\x28\x8c\x28"]);
}
