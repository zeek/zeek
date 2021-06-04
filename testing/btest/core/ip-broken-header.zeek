# This test has a trace that was generated from fuzzing which used to cause
# OOB reads in Zeek. It has a number of packets broken in weird ways.
#
# @TEST-EXEC: gunzip -c $TRACES/trunc/mpls-6in6-broken.pcap.gz | zeek -C -b -r - %INPUT
# @TEST-EXEC: mv weird.log mpls-6in6-broken-wierd.log
# @TEST-EXEC: btest-diff mpls-6in6-broken-wierd.log
# @TEST-EXEC: zeek -C -b -r $TRACES/ip-bogus-header-len.pcap %INPUT
# @TEST-EXEC: mv weird.log ip-bogus-header-weird.log
# @TEST-EXEC: btest-diff ip-bogus-header-weird.log

@load base/frameworks/notice/weird
