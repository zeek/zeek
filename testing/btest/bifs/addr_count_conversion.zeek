# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global v: index_vec;

v = addr_to_counts([2001:0db8:85a3:0000:0000:8a2e:0370:7334]);
print v;
print counts_to_addr(v);
v = addr_to_counts(1.2.3.4);
print v;
print counts_to_addr(v);
