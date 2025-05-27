signature resp-client {
  ip-proto == tcp
  payload /^.*\r\n/
  tcp-state originator
  requires-reverse-signature resp-serialized-server
  enable "Redis"
}

signature resp-serialized-server {
  ip-proto == tcp
  payload /^([-+_,].*\r\n|[:$*#(!=%`~>][+-]?[0-9]+(\.[0-9]*)?\r\n)/
  tcp-state responder
  enable "Redis"
}
