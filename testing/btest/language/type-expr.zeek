# @TEST-DOC: Test valid use of type expressions in scripts
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout

global global_str = string;
global my_global_string: global_str = "hey!!";

event zeek_init()
	{
	local str = string;
	local my_string: str = "hi there :)";
	print my_string;
	print my_global_string;

	local integer = int;
	local my_int: integer = 41;
	my_int += 1;
	print my_int;

	# Try a couple of functions that take types
	print from_json("\"aoeu\"", string);
	print type_name(string);
	}
