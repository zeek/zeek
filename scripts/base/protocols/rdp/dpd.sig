signature dpd_rdp_client {
	ip-proto == tcp
	# Client request
	payload /.*(Cookie: mstshash\=|Duca.*(rdpdr|rdpsnd|drdynvc|cliprdr))/
	requires-reverse-signature dpd_rdp_server
	enable "rdp"
}

signature dpd_rdp_server {
	ip-proto == tcp
	payload /(.{5}\xd0|.*McDn)/
}

signature dpd_rdpeudp_syn {
	ip-proto == udp
	payload-size <= 1232
	payload-size >= 1132
	payload /^\xff{4}.{2}.{1}\x01/
	enable "rdpeudp"
}

