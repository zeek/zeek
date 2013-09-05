#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
{
local a: string = "helloellohello";
local b: string = "abc1234567";

print str_grammer(a, 3);
print str_grammer(b, 4);
}
