# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff .stdout

export {
	## Test some documentation here!
	option testbool: bool = T;
}

function option_changed(ID: string, new_value: bool): bool {
	print fmt("Value of %s changed from %s to %s", ID, testbool, new_value);
	return new_value;
}

function option_changed_two(ID: string, new_value: bool, location: string): bool {
	print fmt("Higher prio - Value of %s changed from %s to %s at location '%s'", ID, testbool, new_value, location);
	return T;
}

event zeek_init()
	{
	print "Old value", testbool;
	Option::set_change_handler("testbool", option_changed);
	Option::set_change_handler("testbool", option_changed_two, 99);
	Option::set("testbool", F);
	Option::set("testbool", F, "here");
	print "New value", testbool;
	}

