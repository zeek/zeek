# @TEST-EXEC: bro -r $TRACES/dns-session.trace %INPUT 
# @TEST-EXEC: btest-diff dns.log

@load protocols/dns/auth-addl
