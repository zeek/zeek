#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "1";
	print count_to_v4_addr(to_count(a));
	
	a = "806716794";
	print count_to_v4_addr(to_count(a));
	
	a = "4294967295";
	print count_to_v4_addr(to_count(a));
	
	# This *should* fail and return 0.0.0.0 since it's 255.255.255.255 + 1
	# Note: How do I check for runtime errors?
	a = "4294967296";
	print count_to_v4_addr(to_count(a));
	}
