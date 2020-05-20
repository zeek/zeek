#@TEST-EXEC: zeek -b -C -r $TRACES/smb/smb1_transaction2_request.pcap %INPUT
#@TEST-EXEC: btest-diff .stdout

@load base/protocols/smb
@load base/protocols/smb

# Check that smb1_transaction2 requests are parsed correctly

event smb1_transaction2_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Args, sub_cmd: count)
{
	print fmt("smb1_transaction2_request hdr: %s, args: %s, sub_cmd: %x", hdr, args, sub_cmd);
}
