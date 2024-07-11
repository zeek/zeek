# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto dtest.spicy ./dtest.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT | sort >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test special-casing the mapping of spicy::Protocol to Zeek's transport_proto.

event dtest_one(x: transport_proto) {
    print x, enum_to_int(x);
}

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_DTEST, 22/tcp);
}

# @TEST-START-FILE dtest.evt

import spicy;

protocol analyzer spicy::dtest over TCP:
    parse originator with dtest::Message;

on dtest::Message -> event dtest_one(spicy::Protocol::TCP);
on dtest::Message -> event dtest_one(spicy::Protocol::UDP);
on dtest::Message -> event dtest_one(spicy::Protocol::ICMP);
on dtest::Message -> event dtest_one(spicy::Protocol::Undef);
on dtest::Message -> event dtest_one(self.p_tcp);
on dtest::Message -> event dtest_one(self.p_udp);
on dtest::Message -> event dtest_one(self.p_icmp);
on dtest::Message -> event dtest_one(self.p_undef);

export spicy::Protocol;

# @TEST-END-FILE
# @TEST-START-FILE dtest.spicy

module dtest;

import spicy;

public type Message = unit {
  sswitch: uint8;
  result_: uint8;

  var p_tcp: spicy::Protocol = spicy::Protocol::TCP;
  var p_udp: spicy::Protocol = spicy::Protocol::UDP;
  var p_icmp: spicy::Protocol = spicy::Protocol::ICMP;
  var p_undef: spicy::Protocol = cast<spicy::Protocol>(42);
};

# @TEST-END-FILE
