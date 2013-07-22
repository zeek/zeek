signature dpd_pop3_server {
  ip-proto == tcp
  payload /^\+OK/
  requires-reverse-signature dpd_pop3_client
  enable "pop3"
  tcp-state responder
}

signature dpd_pop3_client {
  ip-proto == tcp
  payload /(|.*[\r\n])[[:space:]]*([uU][sS][eE][rR][[:space:]]|[aA][pP][oO][pP][[:space:]]|[cC][aA][pP][aA]|[aA][uU][tT][hH])/
  tcp-state originator
}
