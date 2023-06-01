# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto dtest.spicy ./dtest.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT | sort >output
# @TEST-EXEC: btest-diff output

event dtest_message(x: dtest::FUNCS) {
    print "dtest_message", x;
}

event dtest_result(y: dtest::RESULT) {
    print "dtest_result", y;
}

type R: record {
    x: dtest::FUNCS;
    y: dtest::RESULT;
};

event dtest_result_tuple(r: R) {
    print "dtest_result_tuple", r$x, r$y;
}

# @TEST-START-FILE dtest.evt

protocol analyzer spicy::dtest over TCP:
    parse originator with dtest::Message,
    port 22/tcp;

on dtest::Message -> event dtest_message(self.func);

on dtest::Message -> event dtest_result(self.sub.result);

on dtest::Message -> event dtest_result_tuple(dtest::bro_result(self));

# @TEST-END-FILE

# @TEST-START-FILE dtest.spicy

module dtest;

public type FUNCS = enum {
 A=0, B=1, C=2, D=3, E=4, F=5, YES=83
};

public type RESULT = enum {
 A, B, C, D, E, F, YES_AGAIN=83
};

public type Message = unit {
  func: uint8 &convert=FUNCS($$);
  sub: SubMessage;
};

public type SubMessage = unit {
  result: uint8 &convert=RESULT($$);
};

public function bro_result(entry: Message) : tuple<FUNCS, RESULT>  {
	return (entry.func, entry.sub.result);
}

# @TEST-END-FILE
