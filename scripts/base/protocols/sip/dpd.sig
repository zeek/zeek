signature dpd_sip {
  ip-proto == udp
  payload /^ ?SIP\/[0-9]\.[0-9](\x0d\x0a| [0-9][0-9][0-9] )/
  enable "sip"
}
