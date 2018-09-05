# @TEST-EXEC: bro -r $TRACES/nsec-test.trace %INPUT
# @TEST-EXEC: btest-diff dns.log

@load protocols/dns/auth-addl
