# @TEST-DOC: Tests parsing of SMB1 Negotiate Request/Response LanMan messages. Primarily exists to test parsing of the timetstamps.
#
# @TEST-EXEC: zeek -r ${TRACES}/smb/cifs_negotiate_lanman.pcap %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

event smb1_negotiate_request(c: connection, hdr: SMB1::Header, dialects: string_vec)
	{
	print "smb1_negotiate_request";
	print hdr;
	print dialects;
	}

event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse)
	{
	print "smb1_negotiate_response";
	print hdr;
	print response;
	print fmt("Parsed Response Server Time: %DT", response$lanman$server_time);
	}
