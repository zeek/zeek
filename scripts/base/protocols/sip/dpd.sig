signature dpd_sip_udp_req {
  ip-proto == udp
  payload /.* SIP\/[0-9]\.[0-9]\x0d\x0a/
  enable "sip"
}

signature dpd_sip_udp_resp {
  ip-proto == udp
  payload /^ ?SIP\/[0-9]\.[0-9](\x0d\x0a| [0-9][0-9][0-9] )/
  enable "sip"
}

# We don't support SIP-over-TCP yet.
#
# signature dpd_sip_tcp {
#   ip-proto == tcp
#   payload /^( SIP\/[0-9]\.[0-9]\x0d\x0a|SIP\/[0-9]\.[0-9] [0-9][0-9][0-9] )/
#   enable "sip_tcp"
# }
