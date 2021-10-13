# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-DOC: Check functionality of a table/set index consisting of optional sub-records.

type SubRec: record {
	str: string;
};

type Rec: record {
	subrec: SubRec &optional;
};

global myset: set[Rec] = set();

local i = Rec();
local j = Rec($subrec=SubRec($str="hi"));
add myset[i];
add myset[j];
print |myset|, myset;

# All membership tests below are expected to evaluate to true.
print i in myset;
print j in myset;
print Rec() in myset;
print Rec($subrec=SubRec($str="hi")) in myset;
print Rec($subrec=SubRec($str="no")) !in myset;

delete myset[i];
delete myset[j];
print |myset|, myset;
print i !in myset;
print j !in myset;
print Rec() !in myset;
print Rec($subrec=SubRec($str="hi")) !in myset;
print Rec($subrec=SubRec($str="no")) !in myset;
