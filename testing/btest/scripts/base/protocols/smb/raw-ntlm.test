#@TEST-EXEC: zeek -b -C -r $TRACES/smb/raw_ntlm_in_smb.pcap %INPUT
#@TEST-EXEC: btest-diff .stdout

@load base/protocols/ntlm
@load base/protocols/smb

# Just verify that the session key is grabbed correctly from NTLM
# carried raw over SMB.

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
	{
	if ( request?$session_key )
		print request$session_key;
	}
