# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.evt test.spicy
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff output
#
# @TEST-DOC: Test error reporting when an Zeek-side event parameter type does not match what Spicy sends.

event Banner::error(i: count) { }

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
}

# @TEST-START-FILE test.spicy
module SSH;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /KAPUTT/;
};
# @TEST-END-FILE

# @TEST-START-FILE test.evt

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner;

on SSH::Banner::magic -> event Banner::error(self.magic); # Error: string -> count

# @TEST-END-FILE
