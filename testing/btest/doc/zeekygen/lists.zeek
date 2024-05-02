# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b -X zeekygen.config %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff autogen-reST-lists.rst

@TEST-START-FILE zeekygen.config
identifier	test_list*	autogen-reST-lists.rst
@TEST-END-FILE

type TestRecord: record {
    field1: bool;
    field2: count;
};

## Yield type is documented/cross-referenced for primitive types.
global test_list0: list of string;

## Yield type is documented/cross-referenced for composite types.
global test_list1: list of TestRecord;

## Just showing an even fancier yield type.
global test_list2: list of list of TestRecord;
