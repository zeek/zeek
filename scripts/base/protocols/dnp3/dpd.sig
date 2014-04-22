
# DNP3 packets always starts with 0x05 0x64 .

signature dpd_dnp3_server {
	ip-proto == tcp
	payload /\x05\x64/
	tcp-state responder
 	enable "dnp3"
}
