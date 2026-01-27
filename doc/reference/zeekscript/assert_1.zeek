event test_1() {
	assert 3 == 3;
	local x = 37;
	assert x > 40;
	print "not reached";
}

event test_2() {
	assert 2 == 2;
	local x = 37;
	assert x > 40, fmt("%s is not greater than 40", x);
	print "not reached";
}

event zeek_init() {
	schedule 0.01sec { test_1() };
	schedule 0.02sec { test_2() };
}
