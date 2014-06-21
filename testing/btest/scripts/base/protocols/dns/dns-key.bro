# Making sure DNSKEY gets logged as such.
#
# @TEST-EXEC: bro -r $TRACES/dns-dnskey.trace
# @TEST-EXEC: btest-diff dns.log
