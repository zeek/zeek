# @TEST-EXEC: zeek -r $TRACES/smb/smb3.pcap %INPUT
# @TEST-EXEC: btest-diff smb_mapping.log
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/smb

# Add a test for SMB2 transform header.
event smb2_transform_header(c: connection, hdr: SMB2::Transform_header)
	{
	print fmt("smb2_transform_header %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, hdr);
	}

