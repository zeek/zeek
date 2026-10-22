# @TEST-DOC: NTLM over SMB2 without NTLMSSP_NEGOTIATE_UNICODE: the AUTHENTICATE user name is OEM-encoded and must not be decoded as UTF-16.
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb2-ntlm-oem-username.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m ntlm.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/conn
@load base/protocols/ntlm
@load base/protocols/smb

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
	{
	print c$id, challenge?$target_name ? challenge$target_name : "no_target_name";
	}
