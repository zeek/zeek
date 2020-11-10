# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

# @TEST-EXEC-FAIL: zeek -b lacks-type-cast.zeek >error 2>&1
# @TEST-EXEC: btest-diff error

local a: any = double_to_time(13.0);
local aa = |a|;
local aaa = |a as time|;
print a, type_name(a);
print aa, type_name(aa);
print aaa, type_name(aaa);
print 1 + (aa as double);
print 1 + aaa;

@TEST-START-FILE lacks-type-cast.zeek
local a: any = double_to_time(13.0);
local aa = |a|;
print 1 + aa;
@TEST-END-FILE
