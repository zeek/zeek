signature dpd_rfb_server {
	ip-proto == tcp
	payload /^RFB/
	requires-reverse-signature dpd_rfb_client
	enable "rfb"
}

signature dpd_rfb_client {
	ip-proto == tcp
	payload /^RFB/
	tcp-state originator
}