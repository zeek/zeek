signature resp-client {
  ip-proto == tcp
  payload /^.*\r\n/
  tcp-state originator
  requires-reverse-signature resp-serialized-server
  event "Found possible Redis client data"
  enable "spicy_Redis"
}

signature resp-serialized-server {
  ip-proto == tcp
  payload /^([-+_,].*\r\n|[:$*#(!=%`~>][+-]?[0-9]+(\.[0-9]*)?\r\n)/
  tcp-state responder
  event "Found Redis server data"
  enable "spicy_Redis"
}
