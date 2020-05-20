# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

@load frameworks/software/vulnerable

type MyRec: record {
	min: count &optional;
	max: count;
};

type Bar: record {
    aaa: count;
    bbb: string &optional;
    ccc: string &optional;
    ddd: string &default="default";
};

const java_1_6_vuln = Software::VulnerableVersionRange(
	$max = Software::Version($major = 1, $minor = 6, $minor2 = 0, $minor3 = 44)
);

const java_1_7_vuln = Software::VulnerableVersionRange(
	$min = Software::Version($major = 1, $minor = 7),
	$max = Software::Version($major = 1, $minor = 7, $minor2 = 0, $minor3 = 20)
);

redef Software::vulnerable_versions += {
	["Java"] = set(java_1_6_vuln, java_1_7_vuln)
};

local myrec: MyRec = MyRec($max=2);
print myrec;
myrec = MyRec($min=7, $max=42);
print myrec;

local data = Bar($aaa=1, $bbb="test");
print data;

print Software::vulnerable_versions;
