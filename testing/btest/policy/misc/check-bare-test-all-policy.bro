# Makes sures test-all-policy.bro (which loads *all* other policy scripts)
# compiles correctly even in bare mode.
# 
# @TEST-EXEC: bro -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load test-all-policy
