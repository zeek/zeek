# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

local s = "0123456789";
print s[1];
print s[1:2];
print s[1:6];
print s[0:20];
print s[-2];
print s[-3:-1];
print s[-1:-10];
print s[-1:0];
print s[-1:5];
print s[20:23];
print s[-20:23];
print s[0:5][2];
print s[0:5][1:3][0];
