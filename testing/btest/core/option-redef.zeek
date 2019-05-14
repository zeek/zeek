# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff .stdout

# options are allowed to be redef-able.
# And they are even redef-able by default.

option testopt = 5 &redef;
redef testopt = 6;
option anotheropt = 6;
redef anotheropt = 7;

event zeek_init() {
	print testopt;
	print anotheropt;
}

