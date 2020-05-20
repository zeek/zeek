#
# @TEST-EXEC: zeek order_rand | sort >out.1
# @TEST-EXEC: zeek order_base | sort >out.2
# @TEST-EXEC: cmp out.1 out.2

@TEST-START-FILE order_rand.zeek

print unique_id("A-");
print unique_id_from(5, "E-");
print unique_id("B-");
print unique_id_from(4, "D-");
print unique_id("C-");
print unique_id_from(5, "F-");

@TEST-END-FILE

@TEST-START-FILE order_base.zeek

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
print unique_id_from(4, "D-");
print unique_id_from(5, "E-");
print unique_id_from(5, "F-");

@TEST-END-FILE

