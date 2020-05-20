# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# set()/table() constructors are allowed to have attributes.  When initializing
# an identifier, those attributes should also apply to it.

const my_set_ctor_init: set[string] = set("test1") &redef;

redef my_set_ctor_init += {
	"test2",
	"test3",
};

redef my_set_ctor_init += set("test4");

const my_table_ctor_init: table[count] of string = table([1] = "test1") &redef &default="nope";

redef my_table_ctor_init += {
    [2] = "test2",
    [3] = "test3",
};

# initializer list versions work the same way.

const my_set_init: set[string] = { "test1" } &redef;

redef my_set_init += {
	"test2",
	"test3",
};

redef my_set_init += set("test4");

const my_table_init: table[count] of string = { [1] = "test1" } &redef &default="nope";

redef my_table_init += {
    [2] = "test2",
    [3] = "test3",
};

redef my_table_init += table([4] = "test4");

# For tables that yield tables, we can apply attributes to the both other and
# inner tables...

global inception_table: table[count] of table[count] of string = table(
    [0] = table([13] = "bar") &default="forty-two"
) &default=table() &default="we need to go deeper";

global inception_table2: table[count] of table[count] of string = {
    [0] = table([13] = "bar") &default="forty-two",
} &default=table() &default="we need to go deeper";

event zeek_init()
	{
	print "my_set_ctor_init";
	print my_set_ctor_init;
	print "";
	print "my_table_ctor_init";
	print my_table_ctor_init;
	print my_table_ctor_init[5];
	print "";
	print "my_set_init";
	print my_set_init;
	print "";
	print "my_table_init";
	print my_table_init;
	print my_table_init[5];
	print "";
	print "inception";
	print inception_table;
	print inception_table[0];
	print inception_table[0][13];
	print inception_table[0][42];
	print inception_table[1];
	print inception_table[1][2];
	print inception_table2;
	print inception_table2[0];
	print inception_table2[0][13];
	print inception_table2[0][42];
	print inception_table2[1];
	print inception_table2[1][2];
	print "";

	# just checking attributes on locals works, too
	print "local table t1";
	local t1: table[count] of string = table([1] = "foo") &default="nope";
	print t1;
	print t1[1];
	print t1[2];
	print "";

	print "local table t2";
	local t2: table[count] of string = {[1] = "foo"} &default="nope";
	print t2;
	print t2[1];
	print t2[2];
	print "";

	# and for empty initializers...
	print "local table t3";
	local t3: table[count] of string = table() &default="nope";
	print t3;
	print t3[1];
	print t3[2];
	print "";

	print "local table t4";
	local t4: table[count] of string = {} &default="nope";
	print t4;
	print t4[1];
	print t4[2];
	print "";

	}
