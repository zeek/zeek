# @TEST-EXEC: bro --doc-scripts %INPUT
# @TEST-EXEC: btest-diff autogen-reST-records.rst

# undocumented record
type SimpleRecord: record {
    field1: bool;
    field2: count;
};

## Here's the ways records and record fields can be documented.
type TestRecord: record {
    ## document ``A``
    A: count;

    B: bool;  ##< document ``B``

    ## and now ``C``
    C: SimpleRecord; ##< is a declared type

    ## sets/tables should show the index types
    D: set[count, bool];
};
