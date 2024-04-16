# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.evt test.spicy
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Zeek/Spicy/misc/resource-usage | sed 's/=[^ ]*/=XXX/g' >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Exercise the misc/resource-usage.zeek script.

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

# @TEST-END-FILE
