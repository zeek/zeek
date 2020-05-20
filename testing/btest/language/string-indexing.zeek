# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local word = "HelpA";
local s = "0123456789";
local indices = vector(-100, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 100);

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

s = "012345";

for ( i in indices )
	print fmt("word[%s] = %s", indices[i], word[indices[i]]);

for ( i in indices )
	print fmt("word[:%s] = %s", indices[i], word[:indices[i]]);

for ( i in indices )
	print fmt("word[%s:] = %s", indices[i], word[indices[i]:]);

print word[:];

print "";

print "A";
print s[1:-1];
print s[1:-2];
print s[1:-3];
print s[1:-4];
print s[1:-5];
print s[1:-6];
print s[1:-7];
print s[1:-8];
print s[1:-9];

print "";

print "B";
print s[-1:-1];
print s[-1:-2];
print s[-1:-3];
print s[-1:-4];

print "";

print "C";
print s[-100:-99];
print s[-100:-2];
print s[-100:0];
print s[-100:2];
print s[-100:100];

print "";

print "D";;
print s[-2:-99];
print s[-2:-3];
print s[-2:-1];
print s[-2:0];
print s[-2:2];
print s[-2:100];

print "";

print "E";;
print s[0:-100];
print s[0:-1];
print s[0:0];
print s[0:2];
print s[0:100];

print "";

print "F";;
print s[2:-100];
print s[2:-1];
print s[2:0];
print s[2:1];
print s[2:4];
print s[2:100];

print "";

print "F";;
print s[100:-100];
print s[100:-1];
print s[100:0];
print s[100:1];
print s[100:4];
print s[100:100];
