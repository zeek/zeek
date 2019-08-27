# @TEST-EXEC: zeek -b -r $TRACES/smb/smb3_negotiate_context.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/smb

event smb2_negotiate_response(c: connection , hdr: SMB2::Header , response: SMB2::NegotiateResponse )
	{
	print response;
	}
