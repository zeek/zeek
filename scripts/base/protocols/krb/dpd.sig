# This is the ASN.1 encoded version and message type headers

signature dpd_krb_udp_requests {
	ip-proto == udp
	payload /(\x6a|\x6c).{1,4}\x30.{1,4}\xa1\x03\x02\x01\x05\xa2\x03\x02\x01/
	enable "krb"
}

signature dpd_krb_udp_replies {
	ip-proto == udp
	payload /(\x6b|\x6d|\x7e).{1,4}\x30.{1,4}\xa0\x03\x02\x01\x05\xa1\x03\x02\x01/
	enable "krb"
}

signature dpd_krb_tcp_requests {
	ip-proto == tcp
	payload /.{4}(\x6a|\x6c).{1,4}\x30.{1,4}\xa1\x03\x02\x01\x05\xa2\x03\x02\x01/
	enable "krb_tcp"
}

signature dpd_krb_tcp_replies {
	ip-proto == tcp
	payload /.{4}(\x6b|\x6d|\x7e).{1,4}\x30.{1,4}\xa0\x03\x02\x01\x05\xa1\x03\x02\x01/
	enable "krb_tcp"
}

