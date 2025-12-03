# @TEST-DOC: Tests that creating a broker store at global scope returns an error
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v "Remove in v9.1:" | $SCRIPTS/diff-remove-abspath' btest-diff out

const x = Broker::create_master("store");
global t: table[string] of count &broker_store="store";
