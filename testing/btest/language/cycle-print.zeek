# @TEST-DOC: Printing self-referential aggregate values via cycles does not crash and emits <cycle>. Regression test for GH #5407.
#
# The test creates cycles. Since values are refcounted, that leaks memory.
# Thus, we disable leak detection.
#
# @TEST-EXEC: ASAN_OPTIONS="$ASAN_OPTIONS:detect_leaks=0" zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# Record with redef self-ref
type A: record { val: count; };
redef record A += { a: A &optional; };

# Record with any self-ref
type AnyRec: record { val: any &optional; };

# Mutual record cycle via any
type Node: record {
    val:  count;
    data: any &optional;
};
global na: Node;
global nb: Node;

# Mutual record cycle via redef
type MA: record { val: count; };
type MB: record { a: MA &optional; };
redef record MA += { b: MB &optional; };

event zeek_init() {
    # Test 1: redef self-ref
    local a: A = [$val=1];
    a$a = a;
    print a;

    # Test 2: any self-ref
    local ar: AnyRec;
    ar$val = ar;
    print ar;

    # Test 3: mutual ref via any
    na = Node($val=1);
    nb = Node($val=2);
    na$data = nb;
    nb$data = na;
    print na;

    # Test 4: redef mutual cycle
    local ma: MA = [$val=1];
    local mb: MB = [$a=ma];
    ma$b = mb;
    print ma;

    # Test 5: vector self-ref via any
    local v: vector of any;
    v[0] = 1;
    v[0] = v;
    print v;

    # Test 6: table self-ref via any
    local t: table[count] of any;
    t[1] = t;
    print t;
}
