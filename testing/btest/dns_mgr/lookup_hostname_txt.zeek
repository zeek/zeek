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
	when ( local txt = lookup_hostname_txt("example.com") )
		{
		# www.example.com has much more TXT entries, we
		# only return "more-network-monitor", however.
		#
		# ;; ANSWER SECTION:
		# www.example.com.        0       IN      TXT     "more-network-monitor" "bro"
		# www.example.com.        0       IN      TXT     "network-monitor" "open-source" "zeek"
		print "TXT", txt;
		terminate();
		}
	timeout 5sec
		{
		print "ERROR timeout";
		terminate();
		}
	}
