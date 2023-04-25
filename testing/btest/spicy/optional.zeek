# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o foo.hlto foo.spicy foo.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace foo.hlto %INPUT > output 2>&1
# @TEST-EXEC: btest-diff output

type R: record {
    x: vector of int &optional;
};

event foo_result_tuple(r: R) {
    print(r);
}

# @TEST-START-FILE foo.evt

protocol analyzer spicy::foo over TCP:
    parse originator with Foo::Message,
    port 22/tcp;

on Foo::Message -> event foo_result_tuple(Foo::bro_result(self));

# @TEST-END-FILE

# @TEST-START-FILE foo.spicy

module Foo;

public type Message = unit {
  : uint8;
  : uint8;
};

public function bro_result(entry: Message) : tuple<optional<uint8>> {
    local y: optional<uint8>;
    return (y, );
}

# @TEST-END-FILE
