signature dhcp_cookie {
  ip-proto == udp
  payload /^.*\x63\x82\x53\x63/
  enable "dhcp"
}