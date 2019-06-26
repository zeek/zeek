# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global v6 = ptr_name_to_addr("2.1.0.1.0.0.0.0.0.0.0.0.0.0.0.0.2.0.8.0.9.0.0.4.0.b.8.f.7.0.6.2.ip6.arpa");
global v4 = ptr_name_to_addr("52.225.125.74.in-addr.arpa");

print v6;
print v4;