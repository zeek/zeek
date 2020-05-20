# @TEST-EXEC: zeek -r $TRACES/smb/smb2.pcap %INPUT
# @TEST-EXEC: btest-diff smb_files.log
# @TEST-EXEC: btest-diff smb_mapping.log
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/smb

# Add some tests for SMB2 create request and response.
event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest)
	{
	print fmt("smb2_create_request %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, request);
	}

event smb2_create_response(c: connection, hdr: SMB2::Header, response: SMB2::CreateResponse)
	{
	print fmt("smb2_create_response %s -> %s:%d %s", c$id$orig_h, c$id$resp_h, c$id$resp_p, response);
	}

event smb2_file_sattr(c: connection, hdr: SMB2::Header, file_id:
                      SMB2::GUID, times: SMB::MACTimes, attrs: SMB2::FileAttrs)
	{
	print fmt("smb2_file_sattr %s -> %s:%d %s MACTimes:%s FileAttrs:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p, file_id, times, attrs);
	}
