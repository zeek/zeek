# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: spicyz --help 2>&1 | grep -q experimental-pir
#
# @TEST-EXEC: spicyz -o legacy.hlto frame-context.evt frame-context.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap legacy.hlto %INPUT >legacy.out
# @TEST-EXEC: btest-diff legacy.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o pir.hlto frame-context.evt frame-context.spicy 2>&1 | grep -q "attached PIR-produced" && echo attached >route
# @TEST-EXEC: btest-diff route
# @TEST-EXEC: zeek -r ${TRACES}/spicy/frame-probe-tcp.pcap pir.hlto %INPUT >pir.out
# @TEST-EXEC: cmp legacy.out pir.out
#
# @TEST-DOC: Shares a `%context` between the two directions of a connection through the experimental Parser IR route. The originator's parser records how many frames it completed and the last kind, and the responder's parser, a different unit, reports what it finds. Each connection has its own context, the context survives the segments that suspend the originator's parser, and a frame that never completes records nothing. The events must match the legacy route.

module probe;

event request_done(c: connection, kind: count, frames: count) {
    print fmt("request %s kind=%d frames=%d", c$id$orig_p, kind, frames);
}

event reply_done(c: connection, kind: count, frames: count, last: count) {
    print fmt("reply %s kind=%d frames=%d last=%d", c$id$orig_p, kind, frames, last);
}

event request_started(c: connection, frames: count, last: count) {
    print fmt("started %s frames=%d last=%d", c$id$orig_p, frames, last);
}

# @TEST-START-FILE frame-context.evt
protocol analyzer spicy::FRAME_CONTEXT over TCP:
    parse originator with FrameContext::Request,
    parse responder with FrameContext::Reply,
    port 9997/tcp;

on FrameContext::Request::%init -> event probe::request_started($conn, self.context().frames, self.context().last);
on FrameContext::Request -> event probe::request_done($conn, self.kind, self.context().frames);
on FrameContext::Reply -> event probe::reply_done($conn, self.kind, self.context().frames, self.context().last);
# @TEST-END-FILE

# @TEST-START-FILE frame-context.spicy
module FrameContext;

type Shared = tuple<frames: uint64, last: uint8>;

type Cell = unit {
    value: uint8;
};

public type Request = unit {
    %context = Shared;

    kind: uint8;

    # The wire count is one less than the number of cells.
    count: uint64 {
        self.count = self.count + 1;
    }

    cells: Cell[] &size=self.count;
    label: bytes &size=2;

    on %done {
        self.context().frames = self.context().frames + 1;
        self.context().last = self.kind;
    }
};

public type Reply = unit {
    %context = Shared;

    kind: uint8;
    count: uint64 {
        self.count = self.count + 1;
    }

    cells: Cell[] &size=self.count;
    label: bytes &size=2;

    on %done {
        self.context().frames = self.context().frames + 100;
    }
};
# @TEST-END-FILE
