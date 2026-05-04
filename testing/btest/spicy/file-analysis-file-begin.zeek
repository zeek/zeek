# @TEST-DOC: Validates that the opening the same file ID multiple times does not trigger assertion errors.
#
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.pcap test.hlto %INPUT

module SSH;

event zeek_init()
        {
        Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
        Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSHX, 22/tcp);
        }

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
    on %init {
        local file_id = zeek::file_begin("text/plain", "F1234567");
        zeek::file_set_size(0, file_id);
    }

    : skip bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    replaces SSH;

protocol analyzer spicy::SSHX over TCP:
    parse with SSH::Banner;
