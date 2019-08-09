signature dpd_openvpn_udp_req {
  ip-proto == udp
  payload /\x38.{8}\x00\x00\x00\x00/
  enable "openvpn"
}

signature dpd_openvpn_udp_resp {
  ip-proto == udp
  payload /\x40.{8}\x01\x00\x00\x00\x00.{8}\x00\x00\x00\x00/
  enable "openvpn"
}
