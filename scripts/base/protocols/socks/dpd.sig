signature dpd_socks4_client {
	ip-proto == tcp
	# '32' is a rather arbitrary max length for the user name.
	payload /^\x04[\x01\x02].{0,32}\x00/
	tcp-state originator
}

signature dpd_socks4_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks4_client
	payload /^\x00[\x5a\x5b\x5c\x5d]/
	tcp-state responder
	enable "socks"
}

signature dpd_socks4_reverse_client {
	ip-proto == tcp
	# '32' is a rather arbitrary max length for the user name.
	payload /^\x04[\x01\x02].{0,32}\x00/
	tcp-state responder
}

signature dpd_socks4_reverse_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks4_reverse_client
	payload /^\x00[\x5a\x5b\x5c\x5d]/
	tcp-state originator
	enable "socks"
}

signature dpd_socks5_client {
	ip-proto == tcp
	# Watch for a few authentication methods to reduce false positives.
	payload /^\x05.[\x00\x01\x02\x03\x05\x06\x07\x08\x09]/
	tcp-state originator
}

signature dpd_socks5_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks5_client
	# Watch for a single authentication method to be chosen by the server or
	# the server to indicate the no authentication is required.
	# From wikipedia:
	# 0x00: No authentication
	# 0x01: GSSAPI (RFC 1961)
	# 0x02: Username/password (RFC 1929)
	# 0x03–0x7F: methods assigned by IANA[11]
	# 0x03: Challenge-Handshake Authentication Protocol
	# 0x04: Unassigned
	# 0x05: Challenge-Response Authentication Method
	# 0x06: Secure Sockets Layer
	# 0x07: NDS Authentication
	# 0x08: Multi-Authentication Framework
	# 0x09: JSON Parameter Block
	# 0x0A–0x7F: Unassigned
	# 0x80–0xFE: methods reserved for private use
	#
	# Keep in sync with dpd_socks5_client, 0xff is "no acceptable methods"
	payload /^\x05[\x00\x01\x02\x03\x05\x06\x07\x08\x09\xff]/
	tcp-state responder
	enable "socks"
}
