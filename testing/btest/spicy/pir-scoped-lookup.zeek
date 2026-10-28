# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: spicyz --help 2>&1 | grep -q experimental-pir
#
# @TEST-EXEC: spicyz -o first-legacy.hlto first.evt first.spicy
# @TEST-EXEC: spicyz -o second-legacy.hlto second.evt second.spicy
# @TEST-EXEC: zeek -r ${TRACES}/spicy/event-probe-two-ports.pcap first-legacy.hlto second-legacy.hlto %INPUT >legacy.out
# @TEST-EXEC: btest-diff legacy.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o first-pir.hlto first.evt first.spicy 2>&1 | grep -q "attached PIR-produced" && echo "first attached" >route
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -o second-pir.hlto second.evt second.spicy 2>&1 | grep -q "attached PIR-produced" && echo "second attached" >>route
# @TEST-EXEC: btest-diff route
# @TEST-EXEC: zeek -r ${TRACES}/spicy/event-probe-two-ports.pcap first-pir.hlto second-pir.hlto %INPUT >pir.out
# @TEST-EXEC: cmp legacy.out pir.out
#
# @TEST-EXEC: spicyz --experimental-pir -D spicy-pir -c first-cxx first.evt first.spicy 2>first.log
# @TEST-EXEC-FAIL: grep -q linker_scope first.log
# @TEST-EXEC: grep -q "foreign function .* \"linked_artifact_scope\"" first.log
# @TEST-EXEC: test "$(grep -c "registerParser(" first-cxx__r__spicy_pir_backend.cc)" = 1
# @TEST-EXEC: test "$(grep -c "register_protocol_analyzer(" first-cxx__r__spicy_pir_backend.cc)" = 1
# @TEST-EXEC: test "$(grep -c "^ *_t_preinit_module();" first-cxx__r__spicy_pir_backend.cc)" = 1
# @TEST-EXEC: test "$(grep -c "= _r__hlt_.*_hlto_scope;" first-cxx__r__spicy_pir_backend.cc)" = 1
#
# @TEST-DOC: Loads two independently built artifacts that define the parser `EventProbe::Message` with different layouts, and
# registers one analyzer from each on a different port. The runtime resolves a parser by its name and the scope of its
# artifact, so each analyzer runs the parser of its own artifact. Both artifacts are compiled through the experimental
# Parser IR route, and the events must match those of the legacy route. The PIR package states the artifact's scope as
# a call to an ordinary foreign function, with no scope operation of its own, and the generated code reads the
# artifact's scope once, in the pre-initialization that registers the analyzer, and registers the parser once.

module probe;

event first_message(c: connection, is_orig: bool, n: count, tail: string) {
    print fmt("first %s %s %d %s", c$id$resp_p, is_orig, n, tail);
}

event second_message(c: connection, is_orig: bool, n: count, tail: string) {
    print fmt("second %s %s %d %s", c$id$resp_p, is_orig, n, tail);
}

# @TEST-START-FILE first.evt
protocol analyzer spicy::EVENT_PROBE_FIRST over UDP:
    parse with EventProbe::Message,
    port 9998/udp;

on EventProbe::Message -> event probe::first_message($conn, $is_orig, EventProbe::event_count(self.length), self.tail);
# @TEST-END-FILE

# @TEST-START-FILE first.spicy
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

# @TEST-START-FILE second.evt
protocol analyzer spicy::EVENT_PROBE_SECOND over UDP:
    parse with EventProbe::Message,
    port 9999/udp;

on EventProbe::Message -> event probe::second_message($conn, $is_orig, EventProbe::event_count(self.length), self.tail);
# @TEST-END-FILE

# @TEST-START-FILE second.spicy
module EventProbe;

type Item = unit {
    value: uint8;
};

public type Message = unit {
    length: uint64;
    items: Item[] &size=self.length;
    tail: bytes &size=2;
};

function adjusted(n: uint64): uint64 { return n + 100; }
public function event_count(n: uint64): uint64 { return adjusted(n); }
# @TEST-END-FILE
