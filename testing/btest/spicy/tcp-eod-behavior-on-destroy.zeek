# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d foo.spicy foo.evt -o foo.hlto
# @TEST-EXEC: zeek -Cr ${TRACES}/http/206_example_b.pcap foo.hlto "Spicy::enable_print=T" >output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Exercise &eod behavior when processing is aborted without a regular connection shutdown; regression test for Zeek #4501.
#
# @TEST-START-FILE foo.spicy
module foo;

import zeek;

public type X = unit {
    : bytes &eod;

    on %init() {
        print "INIT", zeek::conn_id(), zeek::is_orig();
    }

    on %done() {
        print "DONE", zeek::conn_id(), zeek::is_orig(); # should not be called for instance not reaching &eod
    }

    on %error(e: string) {
        print "ERROR: %s - should not show up" % e;
    }

};

# @TEST-END-FILE

# @TEST-START-FILE foo.evt
import foo;

protocol analyzer X over TCP:
    parse with foo::X,
    port 0/tcp-65535/tcp;
# @TEST-END-FILE
