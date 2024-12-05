# @TEST-DOC: Stress tests for the AST optimizer dealing with side effects.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" = "1"
#
# See below for an explanation of this convoluted invocation line.
# @TEST-EXEC: zeek -b -O ZAM -O dump-xform --optimize-func='AST_opt_test_.*' %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# This is a subtle & extensive test of the AST optimizer used by ZAM, in
# particular its CSE = Common Subexpression Elimination functionality, whereby
# it reuses previously computed values rather than recomputing them. This test
# in particular focuses on that functionality in the context of side-effects
# that arise due to either implicit or explicit function calls. The implicit
# ones (such as table &default functions) are the trickiest, because they
# can in principle access or modify state that leads to *other* implicit
# function calls.
#
# Unlike nearly all Zeek BTests, the heart of the output is intermediary
# information produced by "-O dump-xform", not the final output. The dump
# implicitly reveals where the AST optimizer reuses expressions previously
# computed (into temporaries) and where it refrains from doing so because
# in principle the re-use is unsafe due to possible modifications to the
# original expression. Many of the tests print the same set of values twice in
# a row, often to see whether the first "print" requires correctly re-computing
# an expression or inheriting its value from a previous computation. The
# second "print" generally ensures that given the lack of potential
# side-effects, the values from the first "print" are re-used, although for
# some tests they need to instead be re-computed.
#
# If the dumped intermediary information agrees but there's a difference in
# the final output as the Zeek script executes, that reflects a bug subsequent
# to the AST optimizer (typically, this will be in ZAM's low-level optimizer).
#
# Changes to the AST processing used by script optimization can introduce
# benign differences to the intermediary information, such as introducing
# or removing some temporary variables. These require hand inspection to
# determine whether they reflect a problem.
#
# We divide the tests up into a number of different event handlers. This
# keeps the AST for each group of tests from getting too complex (especially
# if later tests wind up reusing values from much earlier tests, which can
# be hard to manually verify for correctness). We enable ZAM optimization
# for *only* those handlers to avoid complications in the output unrelated
# to these tests. We use distinct event handlers, rather than multiple
# handlers for the same event, to avoid coalescence of the handlers. Doing
# this explicitly rather than using "-O no-inline" is preferrable because
# it means the testing still includes any issues that the inliner might
# introduce.
#
# Any time you make a change to the final output the script produces, confirm
# that running Zeek *without* script optimization produces that same output.

########################################################################

# A global that in some contexts is directly modified as a side-effect.
global g1 = 4;

# A global that is never directly modified as a side-effect. However, some
# side effects have Unknown consequences - for those, the optimizer should
# assume that any expression derived from a global value needs to re-computed.
global g2 = 44;

# A table with a safe &default. However, in some contexts the tests will
# introduce other tables with the same type signature whose &default's have
# side effects. Due to the complexity of potential aliasing among Zeek
# container objects of like types, those side effects should be presumed
# to potentially modify this global.
global tbl_c_of_c = table([2] = 3, [3] = 5) &default=456;

# A function with no side effects.
function benign(a: count): count
	{
	return a + 3;
	}

# Calls a BiF that should be known to the optimizer as having no side effects.
function safe_bif(): string
	{
	return fmt("%s", g1 * 7);
	}

# Calls a BiF that the optimizer doesn't know as having no side effects,
# and which should therefore be treated as having Unknown side effects.
function dangerous_bif(): count
	{
	local l = tbl_c_of_c[2];
	clear_table(tbl_c_of_c);
	return l;
	}

event AST_opt_test_1()
	{
	# For the following, the optimizer should reuse "g1 * 2" and
	# "tbl_c_of_c[2]" for the later print's ...
	print g1 * 2, tbl_c_of_c[2];
	print benign(4);
	print g1 * 2, tbl_c_of_c[2];
	print safe_bif();
	print g1 * 2, tbl_c_of_c[2];

	# ... but *not* after this call. In addition, even though the call
	# doesn't modify "g1", it should still be reloaded because
	# the optimizer only knows that the BiF is unsafe = it has Unknown
	# effects.
	print dangerous_bif();
	print g1 * 2, tbl_c_of_c[2];
	print g1 * 2, tbl_c_of_c[2];
	}

########################################################################

# A function that modifies our global-of-interest.
function mod_g1(a: addr): count
	{
	return ++g1;
	}

global tbl_addr_of_count = table([1.2.3.4] = 1001, [2.3.4.5] = 10002) &default=mod_g1;

event AST_opt_test_2()
	{
	# The optimizer should reload "g1" after each tbl_addr_of_count
	# reference, but reuse "g2 * 3" and "tbl_c_of_c[2]", since those
	# can't be affected by mod_g1().
	print g1 * 2, g2 * 3, tbl_c_of_c[2];
	print tbl_addr_of_count[1.2.3.4];
	print g1 * 2, g2 * 3, tbl_c_of_c[2];
	print tbl_addr_of_count[127.0.0.1];
	print g1 * 2, g2 * 3, tbl_c_of_c[2];
	}

########################################################################

# A global that controls whether the following functions change an entry
# in one of our global tables.
global mess_is_active = F;

# We use a separate function for actually changing the global to make sure
# that the AST analysis follows the effects of function calls.
function do_the_messing()
	{
	tbl_c_of_c[2] = 999;
	}

# An &on_change handler that potentially alters the value of the table.
function mess_with_tbl_c_of_c(tbl: table[bool] of count, tc: TableChange, ind: bool, val: count)
	{
	if ( mess_is_active )
		do_the_messing();
	}

global tcc_mod = table([F] = 44, [T] = 55) &on_change=mess_with_tbl_c_of_c;

event AST_opt_test_3()
	{
	# The optimizer should re-use "tbl_c_of_c[2]" in each of the secondary
	# print's, but it should recompute it after each modification to
	# "tcc_mod", even though the first one won't lead to a potential change.
	print tbl_c_of_c[2];
	print tbl_c_of_c[2];

	tcc_mod[F] = 33;

	print tbl_c_of_c[2];
	print tbl_c_of_c[2];

	mess_is_active = T;
	tcc_mod[T] = 66;

	print tbl_c_of_c[2];
	print tbl_c_of_c[2];
	}

########################################################################

# Analogous to tbl_c_of_c but has a function call for its &default.
global tbl_c_of_c2 = table([1] = 4, [4] = 8) &default=benign;

event AST_opt_test_4()
	{
	# In the following, for the duplicated prints the optimizer should
	# reuse the previous values. That includes for the accesses to
	# local_tbl_c_of_c3 (which associates a more complex &default function
	# to "table[count] of count" types).
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], tbl_c_of_c2[10];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], tbl_c_of_c2[10];

	local local_tbl_c_of_c3 = table([4] = 1, [12] = 0)
		&default=function(c: count): count { return benign(c+7) - 2; };

	# We print at this separately to make sure it occurs prior to
	# potentially computing the other elements in the print.
	print local_tbl_c_of_c3[12];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], local_tbl_c_of_c3[12];

	# Same with separate printing here.
	print local_tbl_c_of_c3[10];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], local_tbl_c_of_c3[10];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], local_tbl_c_of_c3[10];

	# This BiF should lead to recomputing of all values, including
	# the local local_tbl_c_of_c3.
	print dangerous_bif();
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], local_tbl_c_of_c3[12];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], local_tbl_c_of_c3[12], local_tbl_c_of_c3[10];
	}

########################################################################

# Used to introduce another global as having side effects, this time in 
# the context of a local table.
global my_exponential = 2.0;

event AST_opt_test_5()
	{
	# A similar test, but this time the second local has side effects,
	# and aliases type-wise with the first local, so expressions with
	# the first local should be recomputed for every access.
	#
	# The notion of aggregate aliases is important because in general
	# with static analysis it can be extremely difficult to tell whether
	# two instances of an aggregate, each with the same type, might in
	# fact refer to the same underlying aggregate value. The optimizer
	# thus needs to play it safe and refrain from only focusing on the
	# instance that directly has the attribute.
	local side_effect_free = table([0] = 0.5, [1] = 1.5);

	print side_effect_free[1];
	print side_effect_free[1];

	local has_side_effects = table([0] = -0.5, [1] = -1.5)
		&default_insert=function(c: count): double
			{
			my_exponential = my_exponential * my_exponential;
			return my_exponential;
			};

	print side_effect_free[1], has_side_effects[2];
	print side_effect_free[1], has_side_effects[2];
	}

########################################################################

global tbl_c_of_b = table([100] = F, [101] = T);
global tbl_s_of_s = table(["1"] = "4", ["4"] = "8") &default="no-side-effects";
global tbl_s_of_s2 = table(["1"] = "4", ["4"] = "8") &default="ultimately-side-effects";

event AST_opt_test_6()
	{
	# Without the final statement of this handler, the second one of these
	# prints would re-use all of the values. However, it instead can only
	# reuse the first three, as explained below.
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], tbl_c_of_b[100], tbl_s_of_s["4"];
	print g1 * 2, tbl_c_of_c[2], tbl_c_of_c2[1], tbl_c_of_b[100], tbl_s_of_s["4"];

	# This should force recomputation of tbl_c_of_b above (because its
	# type aliases with one that has side effects on loads, so loads
	# must not be optimized away) AND THEREFORE also tbl_s_of_s (because
	# those loads affect an alias of its type).
	print table([11] = F)
		&default=function(c: count): bool
			{ tbl_s_of_s2["2"] = "two"; return |tbl_s_of_s2| < 9; };
	}

########################################################################

# Here we test &default side-effects of record constructors. We also use
# this as an opportunity to stress-test propagation of side effects
# when one side effect induces another, and whether AST analysis correctly
# accounts for potential type aliasing.

# Reads a local table - but that should be enough to raise the specter of
# any "table[count] of bool" access side-effects.
function local_table_read(): count
	{
	local l = table([99] = T);
	return l[99] ? 3 : 2;
	}

# The same, but modifies the table instead.
function local_table_mod(): count
	{
	local l = table([99] = T);
	l[99] = F;
	return |l|;
	}

# Tickles "table[count] of bool" access side-effects.
type R1: record {
	a: count &default = local_table_read();
	b: string;
};

# Similar, but for modification side-effects. NOTE: type-compatible with R1.
type R2: record {
	a: count &default = local_table_mod();
	b: string;
};

# Just like R2 but NOT type-compatible with R1.
type R3: record {
	a: count &default = local_table_mod();
	b: string;
	c: int &default = +5;
};

event AST_opt_test_7()
	{
	# In this test, it's not the mere presence of "R1" that affects
	# earlier optimization (like in the previous test), but the execution
	# of its constructor. So the following should proceed with the second
	# completely re-using from the first.
	print tbl_s_of_s["4"];
	print tbl_s_of_s["4"];

	# Here constructing R1 potentially invokes the &default for $a,
	# which reads from a "table[count] of bool", which the previous
	# test (AST_opt_test_6) has set up as potentially affecting values
	# of type "table[string] of string" such as tbl_s_of_s.
	local force_tbl_c_of_c_str_reload = R1($b="match-on-type-of-tbl_c_of_c");
 	print force_tbl_c_of_c_str_reload;
 	print tbl_s_of_s["4"];
	print tbl_s_of_s["4"];

	# Here's a similar sequence but using a record that *modifies*
	# a "table[count] of bool" - which ordinarily should NOT thwart
	# optimization since there's no potential &on_change attribute for
	# such tables ... HOWEVER R2 is type-compatible with R1, so it
	# inherits R1's side-effects, thus this WILL require a reload of
	# tbl_s_of_s["4"].
	local problem_r2 = R2($b="hello");
	print tbl_s_of_s["4"], problem_r2$b;

	# ... THIS however won't, because R3 is not type-compatible with R1,
	# even though it has the same attributes as R2.
	local problem_r3 = R3($b="hello again");
	print tbl_s_of_s["4"], problem_r3$b;
	}

########################################################################

event AST_opt_test_8()
	{
	# This last one is a hum-dinger. The two locals we define introduce
	# mutually recursive side-effects, type-wise: the first sets up that
	# a "table[count, count] of count" can access a "table[double, double]
	# of double", and the latter establishes the converse. First, this
	# setup requires that the profiler doesn't wind up in infinite
	# recursion trying to follow dependencies. Second, it should both
	# spot those *and* turn them into Unknown side-effects ... which
	# means that reuse of expression involving the global g2 - which is
	# never altered anywhere - that crosses an access to such a table
	# should be recomputed, rather than reusing the previous
	# result, because "all bets are off" for Unknown side-effects.

	# The second of these should reuse the previous temporary ...
	print g2 * 5;
	print g2 * 5;

	local l1 = table([1, 3] = 4, [2, 5] = 6)
		&default = function(i1: count, i2: count): count
			{
			local my_tbl = table([1.0, 3.0] = 1e4);
			return double_to_count(my_tbl[1.0, 3.0]);
			};

	local l2 = table([1.0, 3.0] = 4.0, [2.0, 5.0] = 6.0)
		&default = function(d1: double, d2: double): double
			{
			local my_tbl = table([1, 3] = 1000);
			return my_tbl[1, 3];
			};

	# ... as should both of these, since we haven't yet done an *access*
	# to one of the tables.
	print g2 * 5;
	print g2 * 5;

	# Here's an access.
	print l1[3, 8];

	# The first of these should recompute, the second should re-use.
	print g2 * 5;
	print g2 * 5;

	# Here's an access to the other.
	print l2[2.0, 5.0];

	# Again, the first of these should recompute, the second should re-use.
	print g2 * 5;
	print g2 * 5;
	}

########################################################################

event zeek_init()
	{
	event AST_opt_test_1();
	event AST_opt_test_2();
	event AST_opt_test_3();
	event AST_opt_test_4();
	event AST_opt_test_5();
	event AST_opt_test_6();
	event AST_opt_test_7();
	event AST_opt_test_8();
	}
