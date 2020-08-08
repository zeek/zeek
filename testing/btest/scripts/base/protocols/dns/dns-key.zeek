# Making sure DNSKEY gets logged as such.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnssec/dnskey2.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
