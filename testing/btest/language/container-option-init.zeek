# Ensures that an error doesn't print out for option variables
# that are containers. These get automatically initialized so
# there's no need to manually initialize them.

# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

option foo: set[count] &redef;
option foo2: table[count] of count &redef;
option foo3: vector of count &redef;

print |foo|;
print |foo2|;
print |foo3|;