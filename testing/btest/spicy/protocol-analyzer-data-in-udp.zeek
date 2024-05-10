# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.evt test.spicy
# @TEST-EXEC: zeek -B dpd -s test.sig -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T >&2
# @TEST-EXEC: btest-diff syslog.log

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
}

# @TEST-START-FILE test.sig
signature dpd_syslog {
    payload /.*C1/
    enable "Syslog"
}
# @TEST-END-FILE

# @TEST-START-FILE test.spicy
module Test;

import spicy;
import zeek;

public type Foo = unit {
};

on Foo::%init {
    # Specify analyzer.
    zeek::protocol_begin("Syslog", spicy::Protocol::UDP);
    zeek::protocol_data_in(True, b"A1 orig", spicy::Protocol::UDP);
    zeek::protocol_data_in(False, b"A1 resp", spicy::Protocol::UDP);
    zeek::protocol_data_in(True, b"A2 orig", spicy::Protocol::UDP);
    zeek::protocol_data_in(False, b"A2 resp", spicy::Protocol::UDP);
    zeek::protocol_end();

    # Use explicit handle.
    local syslog = zeek::protocol_handle_get_or_create("syslog", spicy::Protocol::UDP);
    zeek::protocol_data_in(True, b"B1 orig", syslog);
    zeek::protocol_data_in(False, b"B1 resp", syslog);
    zeek::protocol_handle_close(syslog);

    # DPD.
    zeek::protocol_begin(spicy::Protocol::UDP);
    zeek::protocol_data_in(True, b"C1 orig", spicy::Protocol::UDP);
    zeek::protocol_data_in(False, b"C1 resp", spicy::Protocol::UDP);
    zeek::protocol_end();

}
# @TEST-END-FILE

# @TEST-START-FILE test.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse originator with Test::Foo,
    replaces SSH;

# @TEST-END-FILE
