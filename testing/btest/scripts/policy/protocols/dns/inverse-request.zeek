# @TEST-EXEC: zeek -r $TRACES/dns-inverse-query.trace %INPUT 
# @TEST-EXEC: test ! -e dns.log

@load protocols/dns/auth-addl
