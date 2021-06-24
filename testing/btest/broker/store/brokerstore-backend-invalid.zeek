# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global b: table[string] of testrec &backend=Broker::MEMORY;
global c: table[string] of count &read_expire=5sec &backend=Broker::MEMORY;
global d: table[string] of count &broker_store="store" &backend=Broker::MEMORY;
global f: count &backend=Broker::MEMORY;
