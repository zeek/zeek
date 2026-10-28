# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: spicyz --help 2>&1 | grep -q experimental-pir
#
# @TEST-EXEC: spicyz -o legacy.hlto event-probe.evt event-probe.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/event-probe-udp.pcap legacy.hlto %INPUT >legacy.out
# @TEST-EXEC: btest-diff legacy.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o pir.hlto event-probe.evt event-probe.spicy 2>&1 | grep -q "attached PIR-produced" && echo attached >route
# @TEST-EXEC: btest-diff route
# @TEST-EXEC: zeek -r ${TRACES}/spicy/event-probe-udp.pcap pir.hlto %INPUT >pir.out
# @TEST-EXEC: cmp legacy.out pir.out
#
# @TEST-DOC: Parses UDP datagrams through the experimental Parser IR route, with the legacy build of
# the same analyzer as the reference. Each datagram is parsed independently, and the event carries the
# connection, the direction, a count computed by a Spicy helper, and a bytes field. The outputs must match.

module probe;

event message(c: connection, is_orig: bool, n: count, tail: string) {
    print fmt("message %s %s %d %s", c$id, is_orig, n, tail);
}

# @TEST-START-FILE event-probe.evt
protocol analyzer spicy::EVENT_PROBE over UDP:
    parse with EventProbe::Message,
    port 9999/udp;

on EventProbe::Message -> event probe::message($conn, $is_orig, EventProbe::event_count(self.length), self.tail);
# @TEST-END-FILE

# @TEST-START-FILE event-probe.spicy
module EventProbe;

type Item = unit {
    value: uint8;
};

public type Message = unit {
    length: uint64;
    items: Item[] &size=self.length;
    tail: bytes &size=3;
};

function adjusted(n: uint64): uint64 { return n + 1; }
public function event_count(n: uint64): uint64 { return adjusted(n); }
# @TEST-END-FILE
