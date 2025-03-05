# @TEST-GROUP: dns_mgr
#
# @TEST-REQUIRES: dnsmasq --version
# @TEST-PORT: DNSMASQ_PORT

# @TEST-EXEC: btest-bg-run dnsmasq run-dnsmasq 127.0.0.1 ${DNSMASQ_PORT%/tcp}
# @TEST-EXEC: unset ZEEK_DNS_FAKE; ZEEK_DNS_RESOLVER=127.0.0.1:${DNSMASQ_PORT%/tcp} zeek -b %INPUT >out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

const caddrs = blocking_lookup_hostname("dns.example.com");

event zeek_init()
	{
	print "zeek_init";
	local addrs = blocking_lookup_hostname("example.com");
	print "addrs", addrs;
	}

event zeek_done()
	{
	print "zeek_done";
	print "caddrs", caddrs;
	}
