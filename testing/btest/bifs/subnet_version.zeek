# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

print is_v4_subnet(1.2.3.4/16);
print is_v4_subnet([2607:f8b0:4005:801::200e]/64);
print is_v6_subnet(1.2.3.4/24);
print is_v6_subnet([2607:f8b0:4005:801::200e]/12);
