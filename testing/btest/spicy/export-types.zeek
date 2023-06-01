# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o export.hlto export.spicy export.evt >>output
# @TEST-EXEC: zeek export.hlto %INPUT >>output
#
# Zeek 5.0 doesn't include the ID when printing the enum type
# @TEST-EXEC: cat output | sed 's/enum Test::type_enum/enum/g' >output.tmp && mv output.tmp output
#
# Zeek 6.0 includes information on whether a record field is `&optional`.
# @TEST-EXEC: cat output | sed 's/, optional=F//g' >output.tmp && mv output.tmp output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test the `export` keyword to automatically create corresponding Zeek types.

module Test;

global e: Test::type_enum = Test::type_enum_B;
global u2: type_record_u2 = [$t=[$x="S", $y=T]];
global u: Test::type_record_u = [$s="S", $b=T, $u2=u2];
global s: XYZ::type_record_sss = [
    $a=1.2.3.4,
    $b="bytes",
    $e=e,
    $i=-10,
    $iv=5secs,
    $j=10,
    $m=table([4.3.2.1] = "addr1", [4.3.2.2] = "addr2"),
    $o="string",
    $p=42/tcp,
    $r=3.14,
    $s=set(Test::type_enum_A, Test::type_enum_B),
    $t=network_time(),
    $u=u,
    $v=vector("1", "2", "3")
];

event zeek_init() {
    local all_globals: vector of string;
    for ( id in global_ids() )
	all_globals[|all_globals|] = id;

    sort(all_globals, strcmp);

    for ( i in all_globals ) {
	id = all_globals[i];

	if ( ! (/((Test|XYZ)::|type_record_u2)/ in id) )
	    next;

	if ( /type_record_/ in id )
            print id, record_fields(id);
	# else if ( /type_enum$/ in id )
	#     print id, enum_names(id); # Not available in 5.0 yet
	else
	    print id;
    }

    print "---";
    print s;
}

# @TEST-START-FILE export.spicy
module Test;

type type_enum = enum { A, B, C };

type type_record_s = struct {
    a: addr;
    b: bytes;
    e: type_enum;
    i: int32;
    iv: interval;
    j: uint8;
    m: map<addr, string>;
    o: optional<string>;
    p: port;
    r: real;
    s: set<type_enum>;
    t: time;
    u: type_record_u;
    v: vector<string>;
};

type type_record_u = unit {
    var s: string;
    var b: bool;
    var u2: type_record_u2;
};

type type_record_u2 = unit {
    var t: tuple<x: string, y: bool>;
};

# @TEST-END-FILE

# @TEST-START-FILE export.evt

export Test::type_enum;
export Test::type_record_s as XYZ::type_record_sss;
export Test::type_record_u;
export Test::type_record_u2 as type_record_u2;

# @TEST-END-FILE
