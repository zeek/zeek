##! Perform validation of stapled OCSP responses.
#!
#! Note: this _only_ performs validation of stapled OCSP responded. It does
#! not validate OCSP responses that are retrieved via HTTP, because we do not
#! have a mapping to certificates.


@load base/frameworks/notice
@load base/protocols/ssl

module SSL;

export {
	redef enum Notice::Type += {
		## This indicates that the OCSP response was not deemed
		## to be valid.
		Invalid_Ocsp_Response
	};

	redef record Info += {
		## Result of ocsp validation for this connection.
		ocsp_status: string &log &optional;
		## ocsp response as string.
		ocsp_response: string &optional;
	};

}

# SHA256 hash values for recently validated chains along with the OCSP validation
# status are kept in this table to avoid constant validation every time the same
# certificate chain is seen.
global recently_ocsp_validated: table[string] of string = table() &read_expire=5mins;

event ssl_stapled_ocsp(c: connection, is_client: bool, response: string) &priority=3
	{
	c$ssl$ocsp_response = response;
	}

event ssl_established(c: connection) &priority=3
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 || !c$ssl?$ocsp_response )
		return;

	local hash = c$ssl$cert_chain[0]$sha1;
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	local chain_fuids = "";
	for ( i in c$ssl$cert_chain )
		chain_fuids += cat(c$ssl$cert_chain[i]$fuid, ",");

	local reply_id = cat(sha256_hash(c$ssl$ocsp_response), chain_fuids);

	if ( reply_id in recently_ocsp_validated )
		{
		c$ssl$ocsp_status = recently_ocsp_validated[reply_id];
		return;
		}

	local result = x509_ocsp_verify(chain, c$ssl$ocsp_response, root_certs);
	c$ssl$ocsp_status = result$result_string;
	recently_ocsp_validated[reply_id] = result$result_string;

	if( result$result_string != "good" )
		{
		local message = fmt("OCSP response validation failed with (%s)", result$result_string);
		NOTICE([$note=Invalid_Ocsp_Response, $msg=message,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$ocsp_status)]);
		}
	}
