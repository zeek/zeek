# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.evt test.spicy
# @TEST-EXEC: HILTI_DEBUG=zeek zeek -r ${TRACES}/ssh/single-conn.trace misc/dump-events test.hlto %INPUT
# Zeek versions differ in their quoting of the newline character in analyzer.log (two slashes vs one).
# @TEST-EXEC: cat analyzer.log | sed 's#\\\\#\\#g' >analyzer.log.tmp && mv analyzer.log.tmp analyzer.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff analyzer.log
#
# @TEST-DOC: Trigger parse error after confirmation, should be recorded in analyzer.log

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
}

# @TEST-START-FILE test.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/ { zeek::confirm_protocol(); }
    version : /[^-]*/;
    dash    : /-/;
    software: /KAPUTT/;
};
# @TEST-END-FILE

# @TEST-START-FILE test.evt

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner
    # With Zeek < 5.0, DPD tracking doesn't work correctly for replaced
    # analyzers because the ProtocolViolation() doesn't take a tag.
    #
    # replaces SSH
    ;

# @TEST-END-FILE
