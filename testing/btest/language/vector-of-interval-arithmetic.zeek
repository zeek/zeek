# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global v1 = vector(1.5, 3.0, 4.5);
global v2 = vector(3 sec, 1 min, 1 hr);

print v1 * v2;
print v2 * v1;
print v1 / v2;
print v2 / v1;
