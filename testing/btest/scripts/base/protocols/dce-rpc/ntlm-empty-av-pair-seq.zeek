# Tests for good parsing/handling of empty NTLM AV Pair sequences.

# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/ntlm-empty-av-sequence.pcap %INPUT
# @TEST-EXEC: btest-diff ntlm.log
# @TEST-EXEC: btest-diff analyzer_failed.log

@load frameworks/analyzer/debug-logging.zeek
@load base/protocols/dce-rpc
@load base/protocols/ntlm

# ntlm by default excludes itself from analyzer logging

redef DPD::ignore_violations = {};
