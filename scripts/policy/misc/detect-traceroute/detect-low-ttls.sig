signature traceroute-detector-ipv4 {
	header ip[8] < 10
	event "match"
}

signature traceroute-detector-ipv6 {
	header ip6[7] < 10
	event "match"
}
