# This tests events not covered by other tests

# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-conn-with-extensions.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ssl

redef SSL::disable_analyzer_after_detection=F;

event ssl_established(c: connection)
	{
	print "Established", c$id$orig_h, c$id$resp_h;
	}

event ssl_handshake_message(c: connection, is_orig: bool, msg_type: count, length: count)
	{
	print "Handshake", c$id$orig_h, c$id$resp_h, is_orig, msg_type, length;
	}

event ssl_change_cipher_spec(c: connection, is_orig: bool)
	{
	print "CCS", c$id$orig_h, c$id$resp_h, is_orig;
	}

event ssl_plaintext_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count)
	{
	print "Plaintext data", c$id$orig_h, c$id$resp_h, is_orig, SSL::version_strings[record_version], content_type, length;
	}

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count)
	{
	print "Encrypted data", c$id$orig_h, c$id$resp_h, is_orig, SSL::version_strings[record_version], content_type, length;
	}
