# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global sn: subnet;
sn = "10.0.0.0/8" as subnet;
print sn, sn == 10.0.0.0/8;
sn = "2607:f8b0::/32" as subnet;
print sn, sn == [2607:f8b0::]/32;
sn = "::ffff:0:0/1" as subnet;
print sn, sn == [::]/1;
sn = "::ffff:0:0/96" as subnet;
print sn, sn == 0.0.0.0/0;
sn = "::ffff:0:0/100" as subnet;
print sn, sn == 0.0.0.0/4;

print "10.0.0.0" ?as subnet;
print "10.0.0.0/222" ?as subnet;
print "don't work" ?as subnet;
