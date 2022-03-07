signature dpd_tls_server {
  ip-proto == tcp
  # SSL3 / TLS Server hello.
  payload /^(\x15\x03[\x00\x01\x02\x03]....)?\x16\x03[\x00\x01\x02\x03]..\x02...((\x03[\x00\x01\x02\x03\x04])|(\x7F[\x00-\x50])).*/
  tcp-state responder
  enable "ssl"
}

signature dpd_tls_client {
  ip-proto == tcp
  # SSL3 / TLS Client hello.
  payload /^\x16\x03[\x00\x01\x02\x03]..\x01...\x03[\x00\x01\x02\x03].*/
  tcp-state originator
  enable "ssl"
}

signature dpd_dtls_client {
  ip-proto == udp
	# Client hello.
	payload /^\x16\xfe[\xff\xfd]\x00\x00\x00\x00\x00\x00\x00...\x01...........\xfe[\xff\xfd].*/
	enable "dtls"
}
