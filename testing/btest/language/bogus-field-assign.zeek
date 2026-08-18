# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

# Zeek used to happily print the value of "5" here.

print $foo=5;
