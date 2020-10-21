# Whois for a domain name
#
# @TEST-EXEC: zeek -b -r $TRACES/whois/whois_domain.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log

@load base/protocols/conn
@load base/protocols/whois
