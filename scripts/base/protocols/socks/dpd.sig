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
	payload /^\x05.[\x00\x01\x02]/
	tcp-state originator
}

signature dpd_socks5_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks5_client
	# Watch for a single authentication method to be chosen by the server or
	# the server to indicate the no authentication is required.
	payload /^\x05(\x00|\x01[\x00\x01\x02])/
	tcp-state responder
	enable "socks"
}


