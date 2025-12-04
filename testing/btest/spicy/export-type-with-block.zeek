# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -D zeek -do export.hlto export.spicy export.evt
# @TEST-EXEC: zeek export.hlto %INPUT -r $TRACES/http/get.trace >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test type export with a block in an if

# @TEST-START-FILE export.spicy
module foo;

public type X = unit {
    x: uint8;
    if ( True ) {
        y: uint8;
    };
    z: uint8;
};
# @TEST-END-FILE

# @TEST-START-FILE export.evt
import foo;

protocol analyzer FOO over TCP:
    parse with foo::X;

export foo::X;

on foo::X -> event foo::test(self);

# @TEST-END-FILE

event foo::test(x: foo::X) {
    print fmt("Found x! %s", x);
}

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_FOO, 80/tcp);
}
