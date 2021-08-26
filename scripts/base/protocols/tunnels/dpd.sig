# Provide DPD signatures for tunneling protocols that otherwise
# wouldn't be detected at all.

signature dpd_teredo {
  ip-proto = udp
  payload /^(\x00\x00)|(\x00\x01)|([\x60-\x6f].{7}((\x20\x01\x00\x00)).{28})|([\x60-\x6f].{23}((\x20\x01\x00\x00))).{12}/
  enable "teredo"
}
