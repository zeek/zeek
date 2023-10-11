# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC-FAIL: zeek -b -r not-a.pcap >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC-FAIL: cat not-a.pcap | zeek -b -r - >output2 2>&1
# @TEST-EXEC: btest-diff output2

@TEST-START-FILE ./not-a.pcap
%PDF-1.5
This isn't an actual pdf file, and neither a PCAP.
@TEST-END-FILE
