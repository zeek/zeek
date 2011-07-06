# @TEST-EXEC: bro -r $TRACES/dns-session.trace %INPUT 
# @TEST-EXEC: btest-diff dns.log

@load dns
@load dns/auth-addl
