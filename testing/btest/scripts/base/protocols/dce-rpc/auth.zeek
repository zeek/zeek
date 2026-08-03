# @TEST-DOC: Tests the dce_rpc_auth event, which reports the security provider and protection level negotiated at the DCE-RPC layer.
#
# The first three traces all negotiate through SPNEGO (auth_type 9).
#
# A full bidirectional exchange at auth_level 6 (privacy). This is the trace that
# checks is_orig against the real direction of each verifier-carrying PDU.
# @TEST-EXEC: zeek -b -DCr $TRACES/dce-rpc/cs_window7-join_stream092.pcap %INPUT >out.privacy
#
# auth_level 5 (integrity). The checksums here are bad, so -C is needed to see
# both directions.
# @TEST-EXEC: zeek -b -DCr $TRACES/dce-rpc/dce_rpc_ntlm.pcapng %INPUT >out.ntlm
#
# auth_level 2 (connect), plus the Kerberos case worth calling out: the AP-REQ sits
# inside the verifier blob, so this layer is the only place the provider shows up.
# @TEST-EXEC: zeek -b -DCr $TRACES/dce-rpc/kerberos135_auth.pcapng %INPUT >out.kerberos
#
# The last two reach the other auth_type values our traces can produce: 10 (0x0a,
# NTLM picked directly instead of through SPNEGO) and 68 (0x44, netlogon, which the
# analyzer only flags as a weird).
#
# @TEST-EXEC: zeek -b -DCr $TRACES/dce-rpc/ntlm-empty-av-sequence.pcap %INPUT >out.ntlm-direct
# @TEST-EXEC: zeek -b -DCr $TRACES/dce-rpc/dce_rpc_netlogon.pcapng %INPUT >out.netlogon
#
# @TEST-EXEC: btest-diff out.privacy
# @TEST-EXEC: btest-diff out.ntlm
# @TEST-EXEC: btest-diff out.kerberos
# @TEST-EXEC: btest-diff out.ntlm-direct
# @TEST-EXEC: btest-diff out.netlogon

@load base/protocols/dce-rpc

# Lower priority than dce_rpc_message below, so each auth line follows the message it
# belongs to. Only PDUs with a non-zero auth_length carry a verifier, so messages
# without one appear on their own.
event dce_rpc_auth(c: connection, is_orig: bool, fid: count, auth_type: count, auth_level: count, auth_context_id: count) &priority=-5
	{
	print fmt("dce_rpc_auth :: is_orig == %s, fid == %s", is_orig, fid);
	print fmt("dce_rpc_auth :: auth_type == %s (%s), auth_level == %s (%s), auth_context_id == %s",
	          auth_type, DCE_RPC::auth_types[auth_type], auth_level, DCE_RPC::auth_levels[auth_level],
	          auth_context_id);
	}

event dce_rpc_message(c: connection, is_orig: bool, fid: count, ptype_id: count, ptype: DCE_RPC::PType) &priority=5
	{
	print fmt("dce_rpc_message :: is_orig == %s, fid == %s, ptype == %s", is_orig, fid, ptype);
	}
