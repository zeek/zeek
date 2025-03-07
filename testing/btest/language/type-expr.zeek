# @TEST-DOC: Test valid use of type expressions in scripts
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout

event zeek_init()
	{
	# Try a couple of functions that take types
	print from_json("\"aoeu\"", string);
	print type_name(string);

	print double;
	print vector of int;
	}
