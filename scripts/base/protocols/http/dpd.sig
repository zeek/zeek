signature dpd_http_client {
  ip-proto == tcp
  payload /^[[:space:]]*(GET|HEAD|POST)[[:space:]]*/
  tcp-state originator
}

signature dpd_http_server {
  ip-proto == tcp
  payload /^HTTP\/[0-9]/
  tcp-state responder
  requires-reverse-signature dpd_http_client
  enable "http"
}
