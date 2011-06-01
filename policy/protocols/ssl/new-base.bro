

module SSL;

export {
	
	## This is the root CA bundle.  By default it is Mozilla's full trusted
	## root CA list.
	# TODO: move the mozilla_root_certs setting into the mozilla file.
	#print mozilla_root_certs;
	const root_certs: table[string] of string = {} &redef;
	#const root_certs: table[string] of string = {} &redef;
	
	
	## This is where you can define root certificates that you want to validate
	## against servers.  For example, you may have a policy that states that 
	## all local certificates must be signed by a specific signing authority.
	## If you specify your local networks with only the specific authority
	## or authorities your policy stipulates here, certificates signed by any
	## other key will not validate.  By default, all servers are validated 
	## against the full ``root_certs`` bundle.
	#const server_validation: table[subnet] of table[string] of string =
	#	{ [0.0.0.0/0] = root_certs } &redef;

	## This is where you can define root certificates that you want to validate
	## against clients.  This is still doing validation against the server
	## certificate chain, but this allows you to define a restricted 
	## list of signing certificate that clients should be seen connecting to. 
	## For example, you may have a tightly controlled network
	## that you **never** want to establish SSL sessions using anything other
	## than certificates signed by a very select list of certificate
	## authorities.  You can define the networks in this variable along with
	## key signing certificates with which they should be allowed to establish
	## SSL connections.  By default, all client connections are validated 
	## against the full ``root_certs`` bundle.
	#const client_validation: table[subnet] of table[string] of string =
	#	{ [0.0.0.0/0] = root_certs } &redef;
}

@load mozilla-root-certs


redef capture_filters += {
	["ssl"] = "tcp port 443",
	["nntps"] = "tcp port 563",
	["imap4-ssl"] = "tcp port 585",
	["sshell"] = "tcp port 614",
	["ldaps"] = "tcp port 636",
	["ftps-data"] = "tcp port 989",
	["ftps"] = "tcp port 990",
	["telnets"] = "tcp port 992",
	["imaps"] = "tcp port 993",
	["ircs"] = "tcp port 994",
	["pop3s"] = "tcp port 995"
};

global ssl_ports = {
	443/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
	989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp,
} &redef;

redef dpd_config += {
	[[ANALYZER_SSL]] = [$ports = ssl_ports]
};

	
#redef SSL::client_validation += table(
#	[128.146.0.0/16] = table(
#		["LOCAL_DER_CERT"] = "ADFADFWEAFASDFASDFA",  
#		["LOCAL_DER_CERT2"] = "ADFADFWEAFASDFASDFA" )
#		#["DER_CERT_1"]     = SSL::root_certs["DER_CERT_1"],
#		#["LOCAL_DER_CERT"] = "ADFADFWEAFASDFASDFA"},
#);
