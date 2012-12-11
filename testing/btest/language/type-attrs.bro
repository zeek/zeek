# @TEST-EXEC: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# A type's attributes should propagate to any variable declaration that uses
# that type (and the value assigned to that variable).  But they can still
# be overriden by attributes in variable declarations.  A variable's
# attributes are inherited by and take precedence over a value's attributes
# on assignment to that variable.

type str_tbl: table[count] of string &default = "n/a";

event bro_init()
    {
	# attrs from type get propagated to variable
    local s: str_tbl;
	# attrs from decl get propagated to variable
	local t: str_tbl &default = "blah";
	# attrs from decl w/ table()/set() ctor get propagated to variable
	local u: str_tbl = table() &default = "hmm";
	s[0] = "s test";
	t[0] = "t test";
	u[0] = "u test";
	s[1] = t[1] = u[1] = "all test";
	print "s vals", s[0], s[1], s[3];
	print "t vals", t[0], t[1], t[2];
	print "u vals", u[0], u[1], u[2];
	s = table() &default = "nope, variable attrs have precedence";
	s[0] = "s test2";
	print "more s vals", s[0], s[1], s[2];
	t = table() &default = "nope, variable attrs have precedence";
	t[0] = "t test2";
	print "more t vals", t[0], t[1], t[2];
	u = table() &default = "nope, variable attrs have precedence";
	u[0] = "u test2";
	print "more u vals", u[0], u[1], u[2];

	local v: table[count] of string;
	v = table() &default = "hello";
	v[0] = "v test";
	print "v vals", v[0], v[1], v[2];

	v = table();
	v[0] = "v test2";
	print "more v vals", v[0], v[1];
    }
