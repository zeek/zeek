# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -do test.hlto test.spicy test.evt
# @TEST-EXEC: zeek -Cr ${TRACES}/udp-packet.pcap test.hlto %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test exporting units with switches.

event TEST_ZEEK::MessageEvt(message: TEST::Message)
	{ print message; }

# @TEST-START-FILE test.spicy
module TEST;

public type Message = unit {
    switch (1) {
        * -> foo: bytes &eod;
    };
};
# @TEST-END-FILE

# @TEST-START-FILE test.evt
import TEST;
protocol analyzer spicy::Test over UDP:
    port 0/udp - 42000/udp,
    parse with TEST::Message;

export TEST::Message;

on TEST::Message -> event TEST_ZEEK::MessageEvt(self);
# @TEST-END-FILE
