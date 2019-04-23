# Trace in we have mpls->ip6->ip6->ip4 where the ip4 packet
# has an invalid IP version.
# @TEST-EXEC: zeek -C -r $TRACES/tunnels/mpls-6in6-6in6-4in6-invalid-version-4.pcap
# @TEST-EXEC: mv weird.log output

# Trace in which we have mpls->ip6->ip6 where the ip6 packet
# has an invalid IP version.
# @TEST-EXEC: zeek -C -r $TRACES/tunnels/mpls-6in6-6in6-invalid-version-6.pcap
# @TEST-EXEC: cat weird.log >> output

# @TEST-EXEC: btest-diff output

@load base/frameworks/notice/weird.bro

