# @TEST-DOC: Cover some error cases for &publish_on_change
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	local mytbl: table[string] of string &publish_on_change=[
		$changes=set(TABLE_ELEMENT_NEW)
	];
	}

# @TEST-START-NEXT
# Empty changes is not allowed.
global tbl1: table[string] of string &publish_on_change=[
	$changes=set(),
];

# @TEST-START-NEXT
function topic_func2(k: string): string
	{
	return k;
	}

# The topic_func2 has just a single string argument, the index has two.
global tbl2: table[string, string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic=topic_func2,
];

# @TEST-START-NEXT
function topic_func3(k0: string, k1: string): count
	{
	return 42;
	}

# The topic_func3 has a wrong return argument
global tbl3: table[string, string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic=topic_func3
];

# @TEST-START-NEXT
# Wrongly typed topic.
global tbl4: table[string, string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$topic=42,
];

# @TEST-START-NEXT
# Just an unknown field for the constructor
global tbl5: table[string, string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
	$unknown="unknown",
];

# @TEST-START-NEXT
global tbl6: table[string, string] of string &publish_on_change=[];

# @TEST-START-NEXT
global tbl7: table[string, string] of string &publish_on_change=42;

# @TEST-START-NEXT
type X: record { };
global tbl8: table[string, string] of string &publish_on_change=X();

# @TEST-START-NEXT
global tbl9: table[string, string] of string &publish_on_change=record(
	$changes=set(),
);

# @TEST-START-NEXT
function make_attr_value(): Cluster::PublishOnChangeAttr
	{
	return Cluster::PublishOnChangeAttr($changes=set());
	}

global tbl10: table[string, string] of string &publish_on_change=make_attr_value();

# @TEST-START-NEXT
global attr_value = Cluster::PublishOnChangeAttr($changes=set());

global tbl11: table[string, string] of string &publish_on_change=attr_value;
