# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -o test.hlto conv.spicy ./conv.evt
# @TEST-EXEC: ASAN_OPTIONS=detect_leaks=0 zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE conv.spicy

module Conv;

public type Test = unit {
    a: bytes &size=5;
    b: int16;
    c: uint16;
    d: bytes &size=1 &convert=3.14;
    e: bytes &size=1 &convert=1.2.3.4;
    f: bytes &size=1 &convert=[2001:0db8::1428:57ab];
    g: bytes &size=1 &convert=True;
    h: bytes &size=1 &convert="MyString";
    i: bytes &size=1 &convert=time(1295415110.5);
    j: bytes &size=1 &convert=interval(4.0);

    var r: MyStruct = [$i = 11];
    var s: set<uint64> = set<uint64>(1,2,3);
    var t: tuple<a: int64, b: string> = (47, "foo"); # Tuple conversion will ignore element names.
    var v: vector<bytes> = vector<bytes>(b"A", b"B", b"C");
    var l: vector<bytes> = vector<bytes>(b"A", b"B", b"C");
    var m: map<int64, string> = map(1: "A", 2: "B", 3: "C");

    on %done { print self; }
};

type MyStruct = struct {
    i: int64;
    s: string &optional;
};

@TEST-END-FILE


@TEST-START-FILE conv.evt

protocol analyzer Conv over TCP:
    parse originator with Conv::Test,
    port 22/tcp;

on Conv::Test -> event conv::test($conn,
                                  $is_orig,
                                  self.a,
                                  self.b,
                                  self.c,
                                  self.d,
                                  self.e,
                                  self.f,
                                  self.g,
                                  self.h,
                                  self.i,
                                  self.j,
                                  self.r,
                                  self.s,
                                  self.t,
                                  self.v,
                                  self.l,
                                  self.m
                                  );

@TEST-END-FILE

type MyRecord: record {
    i: int;
    s: string &optional;
};

event conv::test(x: connection,
                 is_orig: bool,
                 a: string,
                 b: int,
                 c: count,
                 d: double,
                 e: addr,
                 f: addr,
                 g: bool,
                 h: string,
                 i: time,
                 j: interval,
                 r: MyRecord,
                 s: set[count],
                 t: MyRecord,
                 v: vector of string,
                 l: vector of string,
                 m: table[int] of string
                )
    {
    print x$id;
    print is_orig;
    print a;
    print b;
    print c;
    print d;
    print e;
    print f;
    print g;
    print h;
    print i;
    print fmt("%f", j), type_name(j); # print as float as interval format differs between versions
    print r;
    print s;
    print t;
    print v;
    print l;
    print m;
    }
