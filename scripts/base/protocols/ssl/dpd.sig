signature dpd_ssl_server {
  ip-proto == tcp
  # Server hello.
  payload /^((\x15\x03[\x00\x01\x02\x03]....)?\x16\x03[\x00\x01\x02\x03]..\x02...\x03[\x00\x01\x02\x03]|...?\x04..\x00\x02).*/
  requires-reverse-signature dpd_ssl_client
  enable "ssl"
  tcp-state responder
}

signature dpd_ssl_client {
  ip-proto == tcp
  # Client hello.
  payload /^(\x16\x03[\x00\x01\x02\x03]..\x01...\x03[\x00\x01\x02\x03]|...?\x01[\x00\x03][\x00\x01\x02\x03]).*/
  tcp-state originator
}

signature dpd_dtls_client {
  ip-proto == udp
	# Client hello.
	payload /^\x16\xfe[\xff\xfd]\x00\x00\x00\x00\x00\x00\x00...\x01...........\xfe[\xff\xfd].*/
	enable "dtls"
}
