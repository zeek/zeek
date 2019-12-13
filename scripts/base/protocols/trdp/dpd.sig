signature dpd_rfb_server {
	ip-proto == tcp
	payload /^TRDP/
	tcp-state responder
	requires-reverse-signature dpd_trdp_client
	enable "trdp"
}

signature dpd_rfb_client {
	ip-proto == tcp
	payload /^TRDP/
	tcp-state originator
}
