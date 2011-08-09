#
# @TEST-EXEC: bro order_rand | sort >out.1
# @TEST-EXEC: bro order_base | sort >out.2
# @TEST-EXEC: cmp out.1 out.2

@TEST-START-FILE order_rand.bro

print unique_id("A-");
print unique_id_from("beta", "E-");
print unique_id("B-");
print unique_id_from("alpha", "D-");
print unique_id("C-");
print unique_id_from("beta", "F-");

@TEST-END-FILE

@TEST-START-FILE order_base.bro

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
print unique_id_from("alpha", "D-");
print unique_id_from("beta", "E-");
print unique_id_from("beta", "F-");

@TEST-END-FILE

