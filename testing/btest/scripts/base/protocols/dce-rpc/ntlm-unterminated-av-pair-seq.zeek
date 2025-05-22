# Tests for good parsing/handling of unterminated NTLM AV Pair sequences.

# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/ntlm-unterminated-av-sequence.pcap %INPUT
# @TEST-EXEC: btest-diff ntlm.log
# @TEST-EXEC: btest-diff analyzer.log

@load base/protocols/dce-rpc
@load base/protocols/ntlm

# ntlm by default excludes itself from analyzer logging

redef DPD::ignore_violations = {};
