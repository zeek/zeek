signature dpd_smtp_client {
  ip-proto == tcp
  payload /(|.*[\n\r])[[:space:]]*([hH][eE][lL][oO]|[eE][hH][lL][oO])/
  requires-reverse-signature dpd_smtp_server
  enable "smtp"
  tcp-state originator
}

signature dpd_smtp_server {
  ip-proto == tcp
  payload /^[[:space:]]*220[[:space:]-]/
  tcp-state responder
}