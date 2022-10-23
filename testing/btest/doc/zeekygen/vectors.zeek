# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b -X zeekygen.config %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff autogen-reST-vectors.rst

@TEST-START-FILE zeekygen.config
identifier	test_vector*	autogen-reST-vectors.rst
@TEST-END-FILE

type TestRecord: record {
    field1: bool;
    field2: count;
};

## Yield type is documented/cross-referenced for primitive types.
global test_vector0: vector of string;

## Yield type is documented/cross-referenced for composite types.
global test_vector1: vector of TestRecord;

## Just showing an even fancier yield type.
global test_vector2: vector of vector of TestRecord;
