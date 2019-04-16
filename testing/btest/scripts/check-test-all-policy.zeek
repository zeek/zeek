# Makes sures test-all-policy.bro (which loads *all* other policy scripts) compiles correctly.
# 
# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

@load test-all-policy
