# @TEST-DOC: Ensure change handlers do not run when terminating by trying to change an option during zeek_done()
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

export {
	option testbool: bool = T;
}

function option_changed(ID: string, new_value: bool): bool {
	print fmt("Value of %s changed from %s to %s (zeek_is_terminating=%s)", ID, testbool, new_value, zeek_is_terminating());
	return new_value;
}

event zeek_init()
	{
	print "Initial value", testbool;
	Option::set_change_handler("testbool", option_changed);
	local changed = Option::set("testbool", F);
	print "Next value", testbool;
	print "Next changed", changed;
	}

event zeek_done()
	{
	local changed = Option::set("testbool", T);
	print "Final value", testbool;
	print "Final changed", changed;
	}

