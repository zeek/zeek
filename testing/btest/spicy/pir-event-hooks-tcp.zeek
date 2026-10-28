# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: spicyz --help 2>&1 | grep -q experimental-pir
#
# @TEST-EXEC: spicyz -o legacy.hlto frame-probe.evt frame-probe.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap legacy.hlto %INPUT >legacy.out
# @TEST-EXEC: btest-diff legacy.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o pir.hlto frame-probe.evt frame-probe.spicy 2>&1 | grep -q "attached PIR-produced" && echo attached >route
# @TEST-EXEC: btest-diff route
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap pir.hlto %INPUT >pir.out
# @TEST-EXEC: cmp legacy.out pir.out
#
# @TEST-EXEC: spicyz -d -o legacy-debug.hlto frame-probe.evt frame-probe.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap legacy-debug.hlto %INPUT >legacy-debug.out
# @TEST-EXEC: btest-diff legacy-debug.out
# @TEST-EXEC: spicyz --experimental-pir -d -D spicy-pir -o pir-debug.hlto frame-probe.evt frame-probe.spicy 2>&1 | grep -q "attached PIR-produced" && echo attached >route-debug
# @TEST-EXEC: btest-diff route-debug
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap pir-debug.hlto %INPUT >pir-debug.out
# @TEST-EXEC: cmp legacy-debug.out pir-debug.out
#
# @TEST-DOC: Parses TCP streams with the experimental Parser IR route and compares the events with the legacy route. Events come from `%init`, completed fields, and `%done`, so one frame raises several events in a fixed order. A source hook changes a field before the events observe it, and the bound of a later field uses the changed value. The first connection delivers its frame in four segments that split the header, the body, and the trailer, and no event repeats. A false condition and an event without a handler skip the argument computation, which counts its calls (the ignored event has a counter of its own, since the order of events at one hook point is not specified), and a connection that ends inside a frame raises none of the completion events. The debug build logs every event before it checks for a handler, which evaluates the arguments of events that are skipped otherwise, so the counts differ from the plain build in the same way for both routes.

module probe;

event start(c: connection, is_orig: bool) {
    print fmt("start %s %s", c$id$orig_p, is_orig);
}

event kind(c: connection, is_orig: bool, k: count, calls: count) {
    print fmt("kind %s %s %d %d", c$id$orig_p, is_orig, k, calls);
}

event cells(c: connection, is_orig: bool, n: count, ignored: count) {
    print fmt("cells %s %s %d ignored=%d", c$id$orig_p, is_orig, n, ignored);
}

event frame_done(c: connection, is_orig: bool, calls: count, label: string) {
    print fmt("done %s %s %d %s", c$id$orig_p, is_orig, calls, label);
}

# No handler for `ignored`: its arguments must not be computed.

# @TEST-START-FILE frame-probe.evt
protocol analyzer spicy::FRAME_PROBE over TCP:
    parse originator with FrameProbe::Frame,
    parse responder with FrameProbe::Frame,
    port 9997/tcp;

on FrameProbe::Frame::%init -> event probe::start($conn, $is_orig);
on FrameProbe::Frame::kind -> event probe::kind($conn, $is_orig, self.kind, FrameProbe::observe(1));
on FrameProbe::Frame::count -> event probe::cells($conn, $is_orig, self.count, FrameProbe::seen_ignored());
on FrameProbe::Frame if ( self.kind != 0 ) -> event probe::frame_done($conn, $is_orig, FrameProbe::observe(100), self.label);
on FrameProbe::Frame -> event probe::ignored($conn, FrameProbe::observe_ignored());
# @TEST-END-FILE

# @TEST-START-FILE frame-probe.spicy
module FrameProbe;

global calls: uint64 = 0;
global ignored: uint64 = 0;

public function observe(n: uint64): uint64 {
    calls = calls + 1;
    return n + calls;
}

public function observe_ignored(): uint64 {
    ignored = ignored + 1;
    return ignored;
}

public function seen_ignored(): uint64 { return ignored; }

type Cell = unit {
    value: uint8;
};

public type Frame = unit {
    kind: uint8;

    # The wire count is one less than the number of cells; the hook corrects it before the bound uses it.
    count: uint64 {
        self.count = self.count + 1;
    }

    cells: Cell[] &size=self.count;
    label: bytes &size=2;
};
# @TEST-END-FILE
