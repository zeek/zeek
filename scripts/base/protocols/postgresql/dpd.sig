# Enable the analyzer if we see the SSLRequest message and a S|N reply from the server.
signature dpd_postgresql_client_sslrequest {
  ip-proto == tcp
  payload /^\x00\x00\x00\x08\x04\xd2\x16\x2f/
}

signature dpd_postgresql_server_ssl_confirm {
  requires-reverse-signature dpd_postgresql_client_sslrequest
  payload /^[SN]/
  enable "PostgreSQL"
}

signature dpd_postgresql_client_startup_3_x {
  ip-proto == tcp
  # 4 byte length, then protocol version major, minor (16bit each),
  # then expect the "user\x00" parameter to follow. Not sure about
  # other versions, but we likely wouldn't properly parse them anyway.
  payload /^....\x00\x03\x00.{0,256}user\x00/
}

signature dpd_postgresql_server_any_response {
  requires-reverse-signature dpd_postgresql_client_startup_3_x

  # One byte printable message type 4 bytes length. Assumes the first
  # server message is not larger 64k(2^16) so match on \x00\x00 after
  # the first byte.
  payload /^[a-zA-Z0-9]\x00\x00../
  enable "PostgreSQL"
}
