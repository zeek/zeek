# Makes sures test-all-policy.zeek (which loads *all* other policy scripts) compiles correctly.
# 
# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

@load test-all-policy
