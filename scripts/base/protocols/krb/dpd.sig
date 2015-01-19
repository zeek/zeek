signature dpd_krb_udp {
	ip-proto == udp
	payload /\x6c...\x30...\xa1\x03\x02\x05/
	enable "krb"
}


