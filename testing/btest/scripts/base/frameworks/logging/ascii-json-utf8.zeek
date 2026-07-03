#
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_string_escape_policy=JSON::STRING_ESCAPE_POLICY_HEX;
# @TEST-EXEC: mv ssh.log ssh.log.hex
# @TEST-EXEC: btest-diff ssh.log.hex
#
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_string_escape_policy=JSON::STRING_ESCAPE_POLICY_TSV;
# @TEST-EXEC: mv ssh.log ssh.log.tsv
# @TEST-EXEC: btest-diff ssh.log.tsv
#
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_string_escape_policy=JSON::STRING_ESCAPE_POLICY_PUA;
# @TEST-EXEC: mv ssh.log ssh.log.pua
# @TEST-EXEC: btest-diff ssh.log.pua
#
# Test attaching a filter with path ssh-tsv.log to SSH::LOG using TSV escaping.
# @TEST-EXEC: zeek -b %INPUT ssh-add-filter-config-map-tsv.zeek
# @TEST-EXEC: diff -u ssh.log.tsv ssh-tsv.log
# @TEST-EXEC: btest-diff ssh-tsv.log
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

event zeek_init() &priority=5
	{
	Log::create_stream(SSH::LOG, [$columns=Log]);
	}

event zeek_init() &priority=-5
	{
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

	Log::write(SSH::LOG, [$s="\\\\"]);
	Log::write(SSH::LOG, [$s="\t\\t\t"]);
	Log::write(SSH::LOG, [$s="\v\\v\v"]);
	Log::write(SSH::LOG, [$s="\n\\n\n"]);
	Log::write(SSH::LOG, [$s="\\x"]);
	Log::write(SSH::LOG, [$s="\x00"]);
	Log::write(SSH::LOG, [$s="\x01"]);
	Log::write(SSH::LOG, [$s="\x09"]);  # \t
	Log::write(SSH::LOG, [$s="\x0d"]);  # \r
	Log::write(SSH::LOG, [$s="\x80"]);
	Log::write(SSH::LOG, [$s="\xf9"]);
	Log::write(SSH::LOG, [$s="\xff"]);
	Log::write(SSH::LOG, [$s="\\\\x\\abc\\x.exe"]);
	Log::write(SSH::LOG, [$s="\xf9\xf9"]);
	Log::write(SSH::LOG, [$s="byte 9f vs literal backslash x9f: \xf9 vs \\xf9"]);
	# UTF-8 encoded rockets in source:
	Log::write(SSH::LOG, [$s="a rocket 🚀!"]);
	Log::write(SSH::LOG, [$s="a rocket 🚀!\x00 NUL\x00"]);
	# Hex encoded rockets:
	Log::write(SSH::LOG, [$s="a rocket \xf0\x9f\x9a\x80!"]);
	Log::write(SSH::LOG, [$s="a rocket \xf0\x9f\x9a\x80!\x00 NUL\x00"]);
	Log::write(SSH::LOG, [$s="half-a-rocket rocket \xf0\x9f!"]);
	Log::write(SSH::LOG, [$s="half-a-rocket rocket \xf0\x9f!\x00 NUL\x00"]);
	Log::write(SSH::LOG, [$s="half-a-rocket rocket \xf0\x9f and a rocket\xf0\x9f\x9a\x80!"]);
	Log::write(SSH::LOG, [$s="half-a-rocket rocket \xf0\x9f and a rocket\xf0\x9f\x9a\x80!\x00 NUL\x00"]);
	Log::write(SSH::LOG, [$s="\a\b"]);
	Log::write(SSH::LOG, [$s="\\a=\a \\b=\b \\t=\t \\n=\n"]);
	}

# @TEST-START-FILE ssh-add-filter-config-map-tsv.zeek
# Add a separate filter with the tsv policy in the config.
event zeek_init()
	{
	local f = copy(Log::get_filter(SSH::LOG, "default"));

	f$name = "tsv";
	f$path = "ssh-tsv";
	f$config = table(
		["json_string_escape_policy"] = cat(JSON::STRING_ESCAPE_POLICY_TSV),
	);

	Log::add_filter(SSH::LOG, f);
	}
# @TEST-END-FILE
