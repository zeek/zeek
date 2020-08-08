# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-proprietary-encryption.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/rdp

event rdp_client_security_data(c: connection, data: RDP::ClientSecurityData)
	{
	print "rdp_client_security_data", data;
	print "    40-bit flag", data$encryption_methods & 0x00000001 != 0;
	print "   128-bit flag", data$encryption_methods & 0x00000002 != 0;
	print "    56-bit flag", data$encryption_methods & 0x00000008 != 0;
	print "      fips flag", data$encryption_methods & 0x00000010 != 0;
	}
