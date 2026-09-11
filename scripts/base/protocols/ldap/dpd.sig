signature dpd_ldap_client_udp {
  ip-proto == udp
  payload /^\x30([\x05-\x7f]|\x81.|\x82.{2})\x02(\x01.|\x02.{2}|\x03.{3}|\x04.{4})[\x60\x63\x77]/
}

signature dpd_ldap_server_udp {
  ip-proto == udp
  payload /^\x30/
  requires-reverse-signature dpd_ldap_client_udp
  enable "LDAP_UDP"
}

signature dpd_ldap_client_tcp {
  ip-proto == tcp
  payload /^\x30([\x05-\x7f]|\x81.|\x82.{2})\x02(\x01.|\x02.{2}|\x03.{3}|\x04.{4})[\x4a\x60\x63\x66\x68\x6c\x6e\x77]/
}

signature dpd_ldap_server_tcp {
  ip-proto == tcp
  payload /^\x30/
  requires-reverse-signature dpd_ldap_client_tcp
  enable "LDAP_TCP"
}
