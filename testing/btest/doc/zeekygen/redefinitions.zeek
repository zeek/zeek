# @TEST-DOC: Redefinition values are rendered inside a ReST literal block, so they must not carry inline ReST markup.
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b -X zeekygen.config `basename %INPUT`
# @TEST-EXEC: btest-diff-remove-abspath autogen-reST-redefs.rst

# @TEST-START-FILE zeekygen.config
identifier	TestRedef::*	autogen-reST-redefs.rst
# @TEST-END-FILE

@load ./declare-them
@load ./redef-them

# @TEST-START-FILE declare-them.zeek
module TestRedef;

export {
	type Color: enum { RED, GREEN };

	## A boolean.
	const a_bool: bool = T &redef;
	## A count.
	const a_count: count = 0 &redef;
	## An interval.
	const an_interval: interval = 1sec &redef;
	## A string.
	const a_string: string = "original" &redef;
	## A string that gets redef'd to the empty string.
	const an_empty_string: string = "not empty" &redef;
	## An enum.
	const a_color: Color = RED &redef;
	## A set that gets appended to.
	const a_set: set[count] = { 1 } &redef;
	## Redefined with a non-constant expression.
	const an_expr: string = "original" &redef;
	## Redefined, but with the value omitted from the docs.
	const omitted: count = 0 &redef;
}
# @TEST-END-FILE

# @TEST-START-FILE redef-them.zeek
module TestRedef;

redef a_bool = F;
redef a_count = 42;
redef an_interval = 15sec;
redef a_string = "redefined";
redef an_empty_string = "";
redef a_color = GREEN;
redef a_set += { 2, 3 };
redef an_expr = fmt("%s-%s", "a", "b");
## @docs-omit-value
redef omitted = 1;
# @TEST-END-FILE
