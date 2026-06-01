# @TEST-DOC: Test the mime_content_hash and mime_content_hash_sha256 events in isolation and together.
#
# @TEST-EXEC: zeek -b -f 'tcp port 25' -r $TRACES/smtp.pcap base/protocols/conn base/protocols/smtp %INPUT >out
# @TEST-EXEC: btest-diff-cut -m uid history service conn.log
# @TEST-EXEC: btest-diff out

event mime_content_hash(c: connection, content_len: count, hash_value: string)
	{
	print "mime_content_hash", c$uid, content_len, bytestring_to_hexstr(hash_value);
	}

# @TEST-START-NEXT
event mime_content_hash_sha256(c: connection, content_len: count, hash_value: string)
	{
	print "mime_content_hash_sha256", c$uid, content_len, bytestring_to_hexstr(hash_value);
	}

# @TEST-START-NEXT
event mime_content_hash_sha256(c: connection, content_len: count, hash_value: string)
	{
	print "mime_content_hash_sha256", c$uid, content_len, bytestring_to_hexstr(hash_value);
	}

event mime_content_hash(c: connection, content_len: count, hash_value: string)
	{
	print "mime_content_hash", c$uid, content_len, bytestring_to_hexstr(hash_value);
	}
