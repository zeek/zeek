# @TEST-DOC: Regression test for issue #5923 where removing a set from itself should leave it empty
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

global removed = 0;

function count_removals(s: set[count], tpe: TableChange, c: count)
	{
	if ( tpe == TABLE_ELEMENT_REMOVED ) {
		++removed;
	}
	}

event zeek_init()
	{
	local s: set[count] = {1, 2, 3, 4};
	s -= s;
	print "subtract self set", |s|;
	print s;

	local first_set: set[count] = {1, 2, 3, 4};
	local second_set: set[count] = {1, 2, 3, 4};
	first_set -= second_set;
	print "subtract different set same values", |first_set|;
	print first_set;

	local set_a: set[count] = {1, 2, 3, 4};
	local set_b: set[count] = {2, 3};
	set_a -= set_b;
	print "subtract different sets", |set_a|;
	print set_a;

	local ordered_set: set[count] = {1, 2, 3, 4} &ordered;
	ordered_set -= ordered_set;
	print "subtract self ordered set", |ordered_set|;
	print ordered_set;

	local ordered_set_a: set[count] = {1, 2, 3, 4} &ordered;
	local ordered_set_b: set[count] = {2, 3} &ordered;
	ordered_set_a -= ordered_set_b;
	print "subtract different ordered sets", |ordered_set_a|;
	print ordered_set_a;

	local ordered_set_first: set[count] = {1, 2, 3, 4} &ordered;
	local non_ordered_set_b: set[count] = {2, 3};
	ordered_set_first -= non_ordered_set_b;
	print "subtract ordered set with non-ordered set", |ordered_set_first|;
	print ordered_set_first;

	local t: table[count] of string = {[1] = "one", [2] = "two", [3] = "three"};
	t -= t;
	print "subtract self table", |t|;
	print t;

	local first_table: table[count] of string = {[1] = "one", [2] = "two", [3] = "three"};
	local second_table: table[count] of string = {[1] = "one", [2] = "two", [3] = "three"};
	first_table -= second_table;
	print "subtract different table same values", |first_table|;
	print first_table;

	local table_a: table[count] of string = {[1] = "one", [2] = "two", [3] = "three"};
	local table_b: table[count] of string = {[2] = "two"};
	table_a -= table_b;
	print "subtract different tables", |table_a|;
	print table_a;

	local set_for_onchange: set[count] = {1, 2, 3, 4, 5} &on_change=count_removals;
	set_for_onchange -= set_for_onchange;
	print "subtract self set on_change size", |set_for_onchange|;
	print "subtract self set on_change removed count", removed;
	}
