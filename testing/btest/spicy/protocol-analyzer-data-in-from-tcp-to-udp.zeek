# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto dns.spicy ./dns.evt
# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap test.hlto %INPUT
# @TEST-EXEC: btest-diff http.log

# @TEST-START-FILE dns.spicy
module DNS;

import spicy;
import zeek;

public type Packet = unit {
    data: bytes &eod;
};

on Packet::%done {
    zeek::protocol_begin("HTTP", spicy::Protocol::TCP);
    zeek::protocol_data_in(True, b"GET /etc/passwd1 ");
    zeek::protocol_data_in(True, b"HTTP/1.0\r\n\r\n");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    zeek::protocol_end();
}
# @TEST-END-FILE

# @TEST-START-FILE dns.evt

import zeek;

protocol analyzer spicy::DNS over UDP:
    parse originator with DNS::Packet,
    replaces DNS;

# @TEST-END-FILE
