# Tests that an invalid target_info offset in an NTLM Challenge triggers
# an analyzer violation rather than causing a crash or memory exhaustion.

# @TEST-EXEC: zeek -b -r $TRACES/ldap/ntlm-invalid-target-info-offset.pcap %INPUT
# @TEST-EXEC: btest-diff ntlm.log
# @TEST-EXEC: btest-diff analyzer.log

@load base/protocols/ldap
@load base/protocols/ntlm

redef DPD::ignore_violations = {};
