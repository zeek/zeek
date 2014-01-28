##! This script is used to extract host certificates seen on the wire to disk
##! after being converted to PEM files.  The certificates will be stored in
##! a single file, one for local certificates and one for remote certificates.
##!
##! .. note::
##!
##!     - It doesn't work well on a cluster because each worker will write its
##!       own certificate files and no duplicate checking is done across the
##!       cluster so each node would log each certificate.
##!

@load base/protocols/ssl
@load base/utils/directions-and-hosts
@load protocols/ssl/cert-hash

module SSL;

export {
	## Control if host certificates offered by the defined hosts
	## will be written to the PEM certificates file.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	const extract_certs_pem = LOCAL_HOSTS &redef;
}

# This is an internally maintained variable to prevent relogging of
# certificates that have already been seen.  It is indexed on an md5 sum of
# the certificate.
global extracted_certs: set[string] = set() &read_expire=1hr &redef;

event ssl_established(c: connection) &priority=5
	{
	if ( ! c$ssl?$cert )
		return;

	if ( ! addr_matches_host(c$id$resp_h, extract_certs_pem) )
		return;

	if ( c$ssl$cert_hash in extracted_certs )
		# If we already extracted this cert, don't do it again.
		return;

	add extracted_certs[c$ssl$cert_hash];
	local filename = Site::is_local_addr(c$id$resp_h) ? "certs-local.pem" : "certs-remote.pem";
	local outfile = open_for_append(filename);

	print outfile, "-----BEGIN CERTIFICATE-----";

	# Encode to base64 and format to fit 50 lines. Otherwise openssl won't like it later.
	local lines = split_all(encode_base64(c$ssl$cert), /.{50}/);
	local i = 1;
	for ( line in lines )
		{
		if ( |lines[i]| > 0 )
			{
			print outfile, lines[i];
			}
		i+=1;
		}

	print outfile, "-----END CERTIFICATE-----";
	print outfile, "";
	close(outfile);
	}
