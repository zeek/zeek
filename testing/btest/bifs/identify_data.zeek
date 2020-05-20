# Text encodings may vary with libmagic version so don't test that part.
# @TEST-EXEC: zeek -b %INPUT | sed 's/; charset=.*//g' >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	# plain text
	local a = "This is a test";
	print identify_data(a, T);

	# PNG image
	local b = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00";
	print identify_data(b, T);
	}
