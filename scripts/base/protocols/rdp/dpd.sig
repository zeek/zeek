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
        # the datagram needs to be of size 1232
	payload /^.{4}.{2}.{1}\x01.*{1224}/
}

signature dpd_rdpeudp_synack {
	ip-proto == udp
        # the datagram needs to be of size 1232
	payload /^.{4}.{2}.{1}\x05.*{1224}/
	requires-reverse-signature dpd_rdpeudp_syn
	enable "rdpeudp"
}

