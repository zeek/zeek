# Signatures to initiate dynamic protocol detection.

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

signature dpd_ayiya {
  ip-proto = udp
  payload /^..\x11\x29/
  enable "ayiya"
}

signature dpd_teredo {
  ip-proto = udp
  payload /^(\x00\x00)|(\x00\x01)|([\x60-\x6f])/
  enable "teredo"
}

signature dpd_socks4_client {
	ip-proto == tcp
	# '32' is a rather arbitrary max length for the user name.
	payload /^\x04[\x01\x02].{0,32}\x00/
	tcp-state originator
}

signature dpd_socks4_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks4_client
	payload /^\x00[\x5a\x5b\x5c\x5d]/
	tcp-state responder
	enable "socks"
}

signature dpd_socks4_reverse_client {
	ip-proto == tcp
	# '32' is a rather arbitrary max length for the user name.
	payload /^\x04[\x01\x02].{0,32}\x00/
	tcp-state responder
}

signature dpd_socks4_reverse_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks4_reverse_client
	payload /^\x00[\x5a\x5b\x5c\x5d]/
	tcp-state originator
	enable "socks"
}

signature dpd_socks5_client {
	ip-proto == tcp
	# Watch for a few authentication methods to reduce false positives.
	payload /^\x05.[\x00\x01\x02]/
	tcp-state originator
}

signature dpd_socks5_server {
	ip-proto == tcp
	requires-reverse-signature dpd_socks5_client
	# Watch for a single authentication method to be chosen by the server or
	# the server to indicate the no authentication is required.
	payload /^\x05(\x00|\x01[\x00\x01\x02])/
	tcp-state responder
	enable "socks"
}


