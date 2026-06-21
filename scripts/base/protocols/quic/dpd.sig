signature dpd_quic_initial {
	ip-proto == udp
	payload /^[\xC0-\xCF]\x00\x00\x00\x01/
	enable "quic"
}

signature dpd_quic_v2_initial {
	ip-proto == udp
	payload /^[\xD0-\xDF]\x6b\x33\x43\xcf/
	enable "quic"
}
