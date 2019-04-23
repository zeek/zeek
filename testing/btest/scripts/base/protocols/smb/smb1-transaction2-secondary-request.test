#@TEST-EXEC: zeek -b -C -r $TRACES/smb/smb1_transaction2_secondary_request.pcap %INPUT
#@TEST-EXEC: btest-diff .stdout

@load base/protocols/smb
@load base/protocols/smb

# Check that smb1_transaction2_secondary requests are parsed correctly

event smb1_transaction2_secondary_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Sec_Args, parameters: string, data: string)
{
	print fmt("smb1_transaction2_secondary_request hdr: %s, args: %s, params: %s, data: %s", hdr, args, parameters, data);
}
