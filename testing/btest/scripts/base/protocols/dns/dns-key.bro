# Making sure DNSKEY gets logged as such.
#
# @TEST-EXEC: bro -r $TRACES/dnssec/dnskey2.pcap
# @TEST-EXEC: btest-diff dns.log
