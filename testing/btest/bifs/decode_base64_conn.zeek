# @TEST-EXEC: zeek -r $TRACES/smtp.pcap %INPUT >out
# @TEST-EXEC: btest-diff weird.log

event connection_established(c: connection)
	{
	# This should be logged into weird.
	print decode_base64_conn(c$id, "kaputt");
	}
