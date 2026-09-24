# @TEST-DOC: Just test the error reporting for the old &backend, &broker_store and &broker_allow_complex_type attributes
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

global s: set[string] &backend=Broker::MEMORY;

# @TEST-START-NEXT
type testrec: record {
    a: count;
};

global t: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

# @TEST-START-NEXT
global t: table[string] of string &broker_store="store";
