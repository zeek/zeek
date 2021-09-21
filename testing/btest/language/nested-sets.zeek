# @TEST-EXEC: test `zeek -b -G random.seed %INPUT` = "pass"

@TEST-START-FILE random.seed
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
0
@TEST-END-FILE

type r: record {
	b: set[count];
};

type s: set[set[count]];

global foo: set[r];
global bar = set(1,3,5);

add foo[record($b=bar)];

bar = set(5,3,1);
delete foo[record($b=bar)];

if ( |foo| > 0 )
	print "fail";
else
	print "pass";
