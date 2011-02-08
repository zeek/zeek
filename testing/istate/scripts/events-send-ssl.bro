# $Id: events-send.bro,v 1.1.2.1 2005/10/07 01:59:12 sommer Exp $

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract
@load listen-ssl
	
@load capture-events	
	
redef peer_description = "events-send";

# Make sure the HTTP connection really gets out.
# (We still miss one final connection event because we shutdown before
# it gets propagated but that's ok.)
redef tcp_close_delay = 0secs;

redef ssl_ca_certificate = "../../scripts/ca_cert.pem";
redef ssl_private_key = "../../scripts/bro.pem";
redef ssl_passphrase = "my-password";


	
	
