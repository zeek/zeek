# $Id: worm.sig 47 2004-06-11 07:26:32Z vern $

signature nimda {
	ip-proto == tcp
	dst-port == http_ports
	tcp-state established,originator
	http /.*\/((MSDAC|scripts)\/root|winnt\/system32)\/.*c\+dir$/
	event "Nimda"
}

signature codered1 {
	ip-proto == tcp
	dst-port == http_ports
	tcp-state established,originator
	http /.*\.id[aq]\?.*NNNNNNNNNNNNN/
	event "CodeRed 1"
}

signature codered2 {
	ip-proto == tcp
	dst-port == http_ports
	tcp-state established,originator
	http /.*\.id[aq]\?.*XXXXXXXXXXXXX/
	event "CodeRed 2"
}

# Taken from Snort
signature slammer {
	ip-proto == udp
	dst-port == 1434
	payload /.*\x81\xf1\x03\x01\x04\x9b\x81\xf1\x01/
	event "Slammer propagation attempt"
}

signature witty {
	# header udp[0:2] == 4000
	ip-proto == udp
	src-port == 4000
	payload /.*insert witty message here/
	event "Witty propagation attempt"
}
