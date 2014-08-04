# @TEST-EXEC: bro -b -X broxygen.config %INPUT
# @TEST-EXEC: btest-diff autogen-reST-vectors.rst

@TEST-START-FILE broxygen.config
identifier	test_vector*	autogen-reST-vectors.rst
@TEST-END-FILE

type TestRecord: record {
    field1: bool;
    field2: count;
};

## Yield type is documented/cross-referenced for primitize types.
global test_vector0: vector of string;

## Yield type is documented/cross-referenced for composite types.
global test_vector1: vector of TestRecord;

## Just showing an even fancier yield type.
global test_vector2: vector of vector of TestRecord;
