# @TEST-DOC: Tests the modulo bif works as modulo, and % as remainder, for negative numbers
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init() {
	# Modulo cannot be negative
	assert modulo(0, 64) == 0;
	print fmt("0 mod 64: %d", modulo(0, 64));
	assert modulo(-10, 64) == 54;
	print fmt("-10 mod 64: %d", modulo(-10, 64));
	assert modulo(-100, 64) == 28;
	print fmt("-100 mod 64: %d", modulo(-100, 64));

	assert 0 % 64 == 0;
	print fmt("0 percent 64: %d", 0 % 64);
	assert -10 % 64 == -10;
	print fmt("-10 percent 64: %d", -10 % 64);
	assert -100 % 64 == -36;
	print fmt("-100 percent 64: %d", -100 % 64);
}
