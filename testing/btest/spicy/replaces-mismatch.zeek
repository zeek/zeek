# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o ssh.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC-FAIL: zeek -r ${TRACES}/ssh/single-conn.trace ssh.hlto >output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Attempt to replace a packet analyzer with a protocol analyzer

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt

protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp,
    replaces Ethernet; # fail

# @TEST-END-FILE
