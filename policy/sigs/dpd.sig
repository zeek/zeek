# ALS signatures for protocol detection.

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

signature dpd_bittorrenttracker_client {
  ip-proto == tcp
  payload /^.*\/announce\?.*info_hash/
  tcp-state originator
}

signature dpd_bittorrenttracker_server {
  ip-proto == tcp
  payload /^HTTP\/[0-9]/
  tcp-state responder
  requires-reverse-signature dpd_bittorrenttracker_client
  enable "bittorrenttracker"
}

signature dpd_bittorrent_peer1 {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state originator
}

signature dpd_bittorrent_peer2 {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state responder
  requires-reverse-signature dpd_bittorrent_peer1
  enable "bittorrent"
}

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

signature irc_sig3 {
  ip-proto == tcp
  payload /(.*\x0a)*(\x20)*[Ss][Ee][Rr][Vv][Ee][Rr](\x20)+.+\x0a/
}

signature irc_sig4 {
  ip-proto == tcp
  payload /(.*\x0a)*(\x20)*[Ss][Ee][Rr][Vv][Ee][Rr](\x20)+.+\x0a/
  requires-reverse-signature irc_sig3
  enable "irc"
}

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

signature dpd_ssh_client {
  ip-proto == tcp
  payload /^[sS][sS][hH]-/
  requires-reverse-signature dpd_ssh_server
  enable "ssh"
  tcp-state originator
}

signature dpd_ssh_server {
  ip-proto == tcp
  payload /^[sS][sS][hH]-/
  tcp-state responder
}

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

signature dpd_ssl_server {
  ip-proto == tcp
  # Server hello.
  payload /^(\x16\x03[\x00\x01\x02]..\x02...\x03[\x00\x01\x02]|...?\x04..\x00\x02).*/
  requires-reverse-signature dpd_ssl_client
  enable "ssl"
  tcp-state responder
}

signature dpd_ssl_client {
  ip-proto == tcp
  # Client hello.
  payload /^(\x16\x03[\x00\x01\x02]..\x01...\x03[\x00\x01\x02]|...?\x01[\x00\x01\x02][\x02\x03]).*/
  tcp-state originator
}
