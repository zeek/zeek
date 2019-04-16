#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event bro_init()
	{
	print hexstr_to_bytestring("3034");
	print hexstr_to_bytestring("");
	print hexstr_to_bytestring("00");
	print hexstr_to_bytestring("a");
	}
