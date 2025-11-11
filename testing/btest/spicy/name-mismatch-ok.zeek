# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.spicy test.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Ensures that name mismatches between Zeek/Spicy are tolerated, especially for reserved C++ keywords

type laType: record {
	signed: int; # Applies to reserved keywords in C++
	a: int;
	b: int;
	c: int;
};

event test_event(la: laType) {
    print la;
}

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_NAMEMISMATCH, 22/tcp);
}

# @TEST-START-FILE test.evt

protocol analyzer namemismatch over TCP:
    parse originator with Test::Message;

on Test::Message -> event test_event(Test::make_test_value());

# @TEST-END-FILE
# @TEST-START-FILE test.spicy

module Test;

type TestValue = struct {
	signed: int64;
	x: int64;
	y: int64;
	z: int64;
};

public function make_test_value(): TestValue {
	local test: TestValue = [$signed = 42, $x = 1, $y = 2, $z = 3];
	return test;
}

public type Message = unit {
	: uint8;
};
# @TEST-END-FILE
