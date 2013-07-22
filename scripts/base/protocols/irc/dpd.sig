signature irc_client1 {
  ip-proto == tcp
  payload /(|.*[\r\n]) *[Uu][Ss][Ee][Rr] +.+[\n\r]+ *[Nn][Ii][Cc][Kk] +.*[\r\n]/
  requires-reverse-signature irc_server_reply
  tcp-state originator
  enable "irc"
}

signature irc_client2 {
  ip-proto == tcp
  payload /(|.*[\r\n]) *[Nn][Ii][Cc][Kk] +.+[\r\n]+ *[Uu][Ss][Ee][Rr] +.+[\r\n]/
  requires-reverse-signature irc_server_reply
  tcp-state originator
  enable "irc"
}

signature irc_server_reply {
  ip-proto == tcp
  payload /^(|.*[\n\r])(:[^ \n\r]+ )?[0-9][0-9][0-9] /
  tcp-state responder
}

signature irc_server_to_server1 {
  ip-proto == tcp
  payload /(|.*[\r\n]) *[Ss][Ee][Rr][Vv][Ee][Rr] +[^ ]+ +[0-9]+ +:.+[\r\n]/
}

signature irc_server_to_server2 {
  ip-proto == tcp
  payload /(|.*[\r\n]) *[Ss][Ee][Rr][Vv][Ee][Rr] +[^ ]+ +[0-9]+ +:.+[\r\n]/
  requires-reverse-signature irc_server_to_server1
  enable "irc"
}
