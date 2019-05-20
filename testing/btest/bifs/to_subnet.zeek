# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff error

global sn: subnet;
sn = to_subnet("10.0.0.0/8");
print sn, sn == 10.0.0.0/8;
sn = to_subnet("2607:f8b0::/32");
print sn, sn == [2607:f8b0::]/32;
sn = to_subnet("10.0.0.0");
print sn, sn == [::]/0;
