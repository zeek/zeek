# @TEST-GROUP: dns_mgr
#
# @TEST-REQUIRES: dnsmasq --version
# @TEST-PORT: DNSMASQ_PORT

# @TEST-EXEC: btest-bg-run dnsmasq run-dnsmasq 127.0.0.1 ${DNSMASQ_PORT%/tcp}
# @TEST-EXEC: unset ZEEK_DNS_FAKE; ZEEK_DNS_RESOLVER=127.0.0.1:${DNSMASQ_PORT%/tcp} zeek -b %INPUT >out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

event zeek_init()
	{
	# www.example.com is a CNAME for example.com and this
	# results in nothing :-/
	when ( local addrs = lookup_hostname("www.example.com") )
		{
		print "lookup_hostname addrs", |addrs|;
		for ( a in addrs )
			print a;

		# Example.com is a CNAME for www.example.com and a
		# TXT lookup yields example.com. Weird.
		when ( local txt = lookup_hostname_txt("www.example.com") )
			{
			print "lookup_hostname_txt", |txt|, txt;
			terminate();
			}
		timeout 5sec
			{
			print "ERROR lookup_hostname_txt timeout";
			terminate();
			}
		}
	timeout 5sec
		{
		print "ERROR lookup_hostname timeout";
		terminate();
		}
	}
