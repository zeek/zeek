signature dpd_ssh_client {
  ip-proto == tcp
  payload /^[sS][sS][hH]-[12]\./
  requires-reverse-signature dpd_ssh_server
  enable "ssh"
  tcp-state originator
}

signature dpd_ssh_server {
  ip-proto == tcp
  payload /^[sS][sS][hH]-[12]\./
  tcp-state responder
}