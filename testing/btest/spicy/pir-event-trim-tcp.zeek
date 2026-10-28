# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: spicyz --help 2>&1 | grep -q experimental-pir
#
# @TEST-EXEC: spicyz -o legacy.hlto trim-probe.evt trim-probe.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/trim-probe-tcp.pcap legacy.hlto %INPUT >legacy.out
# @TEST-EXEC: btest-diff legacy.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o pir.hlto trim-probe.evt trim-probe.spicy 2>&1 | grep -q "attached PIR-produced" && echo attached >route
# @TEST-EXEC: btest-diff route
# @TEST-EXEC: zeek -r ${TRACES}/spicy/trim-probe-tcp.pcap pir.hlto %INPUT >pir.out
# @TEST-EXEC: cmp legacy.out pir.out
#
# @TEST-DOC: Parses one frame that TCP delivers in five-byte segments, so the parser suspends and resumes inside its header, the length, the byte-bounded vector, and the tail, while the experimental Parser IR route releases input it has consumed. The header bytes and the length are read first and are reported after the whole frame, so they must stay valid once their input was released. The events match the legacy route.

module probe;

event frame(c: connection, is_orig: bool, head: string, size: count, tail: string) {
    print fmt("frame %s %s %s %d %s", c$id$orig_p, is_orig, head, size, tail);
}

# @TEST-START-FILE trim-probe.evt
protocol analyzer spicy::TRIM_PROBE over TCP:
    parse originator with TrimProbe::Frame,
    port 9996/tcp;

on TrimProbe::Frame -> event probe::frame($conn, $is_orig, self.head, self.size, self.tail);
# @TEST-END-FILE

# @TEST-START-FILE trim-probe.spicy
module TrimProbe;

type Item = unit {
    first: uint8;
    second: uint8;
};

public type Frame = unit {
    head: bytes &size=4;
    size: uint64;
    items: Item[] &size=self.size;
    tail: bytes &size=3;
};
# @TEST-END-FILE
