# LDAP messages are BER-encoded (RFC 4511). The client signatures below match
# the LDAPMessage header, followed by the tag of the operation it carries:
#
#   \x30                            SEQUENCE, start of the LDAPMessage
#   [\x05-\x7f]                     message length, short form
#   \x81. \x82.. \x83... \x84....   message length, 1 to 4 byte long form
#   \x02                            INTEGER, start of the messageID
#   \x01. \x02.. \x03... \x04....   1 to 4 byte messageID
#
# The trailing character class holds the tags of the protocolOp choice:
#
#   \x4a delete     \x60 bind       \x63 search     \x66 modify
#   \x68 add        \x6c modifyDN   \x6e compare    \x77 extended

# CLDAP only carries bind, search and extended requests.
signature dpd_ldap_client_udp {
  ip-proto == udp
  payload /^\x30([\x05-\x7f]|\x81.|\x82..|\x83...|\x84....)\x02(\x01.|\x02..|\x03...|\x04....)[\x60\x63\x77]/
}

signature dpd_ldap_server_udp {
  ip-proto == udp
  payload /^\x30/
  requires-reverse-signature dpd_ldap_client_udp
  enable "LDAP_UDP"
}

signature dpd_ldap_client_tcp {
  ip-proto == tcp
  payload /^\x30([\x05-\x7f]|\x81.|\x82..|\x83...|\x84....)\x02(\x01.|\x02..|\x03...|\x04....)[\x4a\x60\x63\x66\x68\x6c\x6e\x77]/
}

signature dpd_ldap_server_tcp {
  ip-proto == tcp
  payload /^\x30/
  requires-reverse-signature dpd_ldap_client_tcp
  enable "LDAP_TCP"
}
