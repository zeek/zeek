# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

print is_v4_addr(1.2.3.4);
print is_v4_addr([::1]);
print is_v6_addr(1.2.3.4);
print is_v6_addr([::1]);
