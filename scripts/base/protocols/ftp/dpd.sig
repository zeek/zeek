signature dpd_ftp_client {
  ip-proto == tcp
  payload /(|.*[\n\r]) *[uU][sS][eE][rR] /
  tcp-state originator
}

# Match for server greeting (220, 120) and for login or passwd
# required (230, 331).
signature dpd_ftp_server {
  ip-proto == tcp
  payload /[\n\r ]*(120|220)[^0-9].*[\n\r] *(230|331)[^0-9]/
  tcp-state responder
  requires-reverse-signature dpd_ftp_client
  enable "ftp"
}
