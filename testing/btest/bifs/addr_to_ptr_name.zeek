# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

print addr_to_ptr_name([2607:f8b0:4009:802::1012]);
print addr_to_ptr_name(74.125.225.52);

