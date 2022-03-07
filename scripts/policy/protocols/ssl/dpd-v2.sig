# This signature can be used to enable DPD for SSL version 2.
# Note that SSLv2 is basically unused by now. Due to the structure of the protocol, it also is sometimes
# hard to disambiguate it from random noise - so you will probably always get a few false positives.

signature dpd_ssl_server {
	ip-proto == tcp
	payload /^...?\x04..\x00\x02.*/
	requires-reverse-signature dpd_ssl_client
	tcp-state responder
	enable "ssl"
}

signature dpd_ssl_client {
	ip-proto == tcp
	payload /^...?\x01[\x00\x03][\x00\x01\x02\x03\x04].*/
	tcp-state originator
}
