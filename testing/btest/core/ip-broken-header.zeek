# This test has a trace that was generated from fuzzing which used to cause
# OOB reads in Bro. It has a number of packets broken in weird ways.
#
# @TEST-EXEC: gunzip -c $TRACES/trunc/mpls-6in6-broken.pcap.gz | zeek -C -b -r - %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird
