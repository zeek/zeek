# Provide DPD signatures for tunneling protocols that otherwise
# wouldn't be detected at all.

signature dpd_ayiya {
  ip-proto = udp
  payload /^..\x11\x29/
  enable "ayiya"
}

signature dpd_teredo {
  ip-proto = udp
  payload /^(\x00\x00)|(\x00\x01)|([\x60-\x6f])/
  enable "teredo"
}
