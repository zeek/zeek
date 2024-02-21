# @TEST-DOC: Deleteing a table, set or vector removes all of its elements.

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff .stderr

global t: table[count] of count &read_expire=1sec;
global s: set[count];
global v = vector(1,2,3);

t[42] = 4711;
add s[42];

print "t", t;
print "s", s;
print "v", v;

delete t;
delete s;
delete v;

print "t", t;
print "s", s;
print "v", v;
