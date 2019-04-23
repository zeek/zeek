# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek -b -X zeexygen.config %INPUT
# @TEST-EXEC: btest-diff autogen-reST-records.rst

@TEST-START-FILE zeexygen.config
identifier	TestRecord*	autogen-reST-records.rst
@TEST-END-FILE

# undocumented record
type TestRecord1: record {
    field1: bool;
    field2: count;
};

## Here's the ways records and record fields can be documented.
type TestRecord2: record {
    ## document ``A``
    A: count;

    B: bool;  ##< document ``B``

    ## and now ``C``
    C: TestRecord1; ##< is a declared type

    ## sets/tables should show the index types
    D: set[count, bool];
};
