#@TEST-EXEC: zeek -b -C -r $TRACES/smb/smb1_transaction_response.pcap %INPUT
#@TEST-EXEC: btest-diff .stdout

@load base/protocols/smb
@load base/protocols/smb

# Check that smb1_transaction_response requests are parsed correctly

event smb1_transaction_response(c: connection, hdr: SMB1::Header, parameters: string, data: string)
{
	print fmt("smb1_transaction_response hdr: %s, params: %s, data: %s", hdr, parameters, data);
}
