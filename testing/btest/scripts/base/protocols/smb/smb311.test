# @TEST-EXEC: zeek -b -C -r $TRACES/smb/smb311.pcap %INPUT
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/smb

# Add some tests for SMB3
event smb2_negotiate_response(c: connection, hdr: SMB2::Header, nr: SMB2::NegotiateResponse)
	{
	print fmt("smb2_negotiate_response %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, nr);
	}
