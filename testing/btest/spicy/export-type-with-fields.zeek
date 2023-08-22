# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -do export.hlto export.spicy export.evt
# @TEST-EXEC: zeek export.hlto %INPUT >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test type export with specified fields.

# @TEST-START-FILE export.spicy
module foo;

public type X = unit {
    x: uint8;
    y: uint8;
    z: uint8;
};
# @TEST-END-FILE

# @TEST-START-FILE export.evt
import foo;

protocol analyzer FOO over TCP:
    parse with foo::X,
    port 80/tcp;

export foo::X with { x };
export foo::X as foo::X1;
export foo::X as foo::X2 &log;
export foo::X as foo::X3 with { x, z &log };
export foo::X as foo::X4 without { x, y };

# @TEST-END-FILE

function printFields(name: string, t: any) {
    print fmt("=== %s", name);
    local fields = record_fields(t);
    for ( f in fields )
	print fmt("name=%s log=%s", f, fields[f]$log);
}

event zeek_init() {
    printFields("X ", foo::X);
    printFields("X1", foo::X1);
    printFields("X2", foo::X2);
    printFields("X3", foo::X3);
    printFields("X4", foo::X4);
}

