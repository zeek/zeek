#@TEST-EXEC: zeek -b -C -r $TRACES/smb/smb1_transaction_request.pcap %INPUT
#@TEST-EXEC: btest-diff .stdout

@load base/protocols/smb
@load base/protocols/smb

# Check that smb1_transaction requests are parsed correctly

event smb1_transaction_request(c: connection, hdr: SMB1::Header, name: string, sub_cmd: count, parameters: string, data: string)
{
	print fmt("smb1_transaction_request hdr: %s, name: %s, sub_cmd: %x, params: %s, data: %s", hdr, name, sub_cmd, parameters, data);
}
