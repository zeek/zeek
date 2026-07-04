# @TEST-DOC: Test some valid &publish_on_change usages.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-START-NEXT
global tbl1: table[string] of string &publish_on_change=[
	$changes=set(TABLE_ELEMENT_NEW),
];

# @TEST-START-NEXT
global tbl2: table[string] of string &publish_on_change=Cluster::PublishOnChangeAttr(
	$changes=set(TABLE_ELEMENT_NEW),
);

# @TEST-START-NEXT
global tbl3: table[string] of string &publish_on_change=record(
	$changes=set(TABLE_ELEMENT_NEW),
);

# @TEST-START-NEXT
function make_attr_value(): Cluster::PublishOnChangeAttr
	{
	return [$changes=set(TABLE_ELEMENT_NEW)];
	}

global tbl4: table[string] of string &publish_on_change=make_attr_value();

# @TEST-START-NEXT
global attr_value = Cluster::PublishOnChangeAttr($changes=set(TABLE_ELEMENT_NEW));

global tbl5: table[string] of string &publish_on_change=attr_value;
