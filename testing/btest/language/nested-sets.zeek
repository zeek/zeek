# @TEST-EXEC: for i in `seq 21`; do echo 0 >> random.seed; done
# @TEST-EXEC: test `zeek -b -G random.seed %INPUT` = "pass"

type r: record {
	b: set[count];
};

global foo: set[r];
global bar = set(1,3,5);

add foo[record($b=bar)];

bar = set(5,3,1);
delete foo[record($b=bar)];

if ( |foo| > 0 )
	print "fail";
else
	print "pass";
