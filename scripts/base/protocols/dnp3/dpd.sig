
signature dpd_dnp3_client {
	ip-proto == tcp
	# dnp3 packets always starts with 0x05 0x64 .
	payload /\x05\0x64/
	tcp-state originator
}

signature dpd_dnp3_server {
	ip-proto == tcp
	# dnp3 packets always starts with 0x05 0x64 .
	payload /\x05\x64/
	tcp-state responder
 	enable "dnp3"
}
