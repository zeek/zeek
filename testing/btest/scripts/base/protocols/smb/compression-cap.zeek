# @TEST-EXEC: zeek -b -r $TRACES/smb/SMBGhost.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/smb

event smb2_negotiate_response(c: connection, hdr: SMB2::Header, response: SMB2::NegotiateResponse)
	{
	for ( i in response$negotiate_context_values )
		{
		local ncv = response$negotiate_context_values[i];

		print fmt("context value type %s, length %s",
		          ncv$context_type, ncv$data_length);

		switch ( ncv$context_type ) {
		case 0x001:
			print fmt("  %s", ncv$preauth_info);
			break;
		case 0x002:
			print fmt("  %s", ncv$encryption_info);
			break;
		case 0x003:
			print fmt("  %s", ncv$compression_info);
			break;
		case 0x005:
			print fmt("  %s", ncv$netname);
			break;
		default:
			print "  unknown context value type";
			break;
		}
		}
	}
