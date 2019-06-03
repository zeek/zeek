signature dpd_ntp {

 	ip-proto == udp


 	# ## TODO: Define the payload. When Bro sees this regex, on
	# ## any port, it will enable your analyzer on that
	# ## connection.
	# ## payload /^NTP/

 	enable "ntp"
}
