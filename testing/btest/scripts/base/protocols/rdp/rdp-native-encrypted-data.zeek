# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-proprietary-encryption.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/rdp

event rdp_native_encrypted_data(c: connection, orig: bool, len: count)
	{
	print "rdp native encrypted data", orig, len;

	if ( ! orig )
		# That's fine to stop here, we don't need to check the entire
		# encrypted conversation for the purpose of the unit test.
		terminate();
	}
