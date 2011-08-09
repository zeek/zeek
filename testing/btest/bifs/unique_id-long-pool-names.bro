# Tests to ensure that collisions are resolved correctly.  Note that pools only use the
# first 32 characters of their name to generate randomness.  Thus, hashes of pools with
# more than 32 characters will be the same, inducing a collision.  When this happens,
# the hash is repeated until an unused instance ID is determined.  
#
# The order here is expected to be deterministic *if and only if* the first entries for
# each individual pool are created in a common order (e.g. ...7890 is created before 
# ...7891 is created before ...7892).
#
# @TEST-EXEC: bro order_rand | sort >out.1
# @TEST-EXEC: bro order_base | sort >out.2
# @TEST-EXEC: cmp out.1 out.2

@TEST-START-FILE order_rand.bro

print unique_id_from("1234567890123456789012345678901234567890", "A-");
print unique_id_from("1234567890123456789012345678901234567891", "B-");
print unique_id_from("1234567890123456789012345678901234567890", "C-");
print unique_id_from("1234567890123456789012345678901234567891", "D-");
print unique_id_from("1234567890123456789012345678901234567890", "E-");
print unique_id_from("1234567890123456789012345678901234567892", "F-");

@TEST-END-FILE

@TEST-START-FILE order_base.bro

print unique_id_from("1234567890123456789012345678901234567890", "A-");
print unique_id_from("1234567890123456789012345678901234567890", "C-");
print unique_id_from("1234567890123456789012345678901234567890", "E-");
print unique_id_from("1234567890123456789012345678901234567891", "B-");
print unique_id_from("1234567890123456789012345678901234567891", "D-");
print unique_id_from("1234567890123456789012345678901234567892", "F-");

@TEST-END-FILE

