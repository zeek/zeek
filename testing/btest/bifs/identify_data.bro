#
# @TEST-EXEC: bro %INPUT | sed 's/PNG image data/PNG image/g' >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	# plain text
	local a = "This is a test";
	print identify_data(a, F);
	print identify_data(a, T);

	# PNG image
	local b = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";
	print identify_data(b, F);
	print identify_data(b, T);
	}
