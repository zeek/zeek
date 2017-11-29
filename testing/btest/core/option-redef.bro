# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

# options are allowed to be redef-able.

option testopt = 5 &redef;
redef testopt = 6;

event bro_init() {
	print testopt;
}

