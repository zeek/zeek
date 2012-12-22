@load ./consts

module SSL;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the SSL connection was first detected.
		ts:               time             &log;
		## Unique ID for the connection.
		uid:         string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id          &log;
		## SSL/TLS version that the server offered.
		version:          string           &log &optional;
		## SSL/TLS cipher suite that the server chose.
		cipher:           string           &log &optional;
		## Value of the Server Name Indicator SSL/TLS extension.  It
		## indicates the server name that the client was requesting.
		server_name:      string           &log &optional;
		## Session ID offered by the client for session resumption.
		session_id:       string           &log &optional;
		## Subject of the X.509 certificate offered by the server.
		subject:          string           &log &optional;
		## Subject of the signer of the X.509 certificate offered by the server.
		issuer_subject:   string           &log &optional;
		## NotValidBefore field value from the server certificate.
		not_valid_before: time             &log &optional;
		## NotValidAfter field value from the server certificate.
		not_valid_after:  time             &log &optional;
		## Last alert that was seen during the connection.
		last_alert:       string           &log &optional;

		## Subject of the X.509 certificate offered by the client.
		client_subject:          string           &log &optional;
		## Subject of the signer of the X.509 certificate offered by the client.
		client_issuer_subject:   string           &log &optional;

		## Full binary server certificate stored in DER format.
		cert:             string           &optional;
		## Chain of certificates offered by the server to validate its
		## complete signing chain.
		cert_chain:       vector of string &optional;

		## Full binary client certificate stored in DER format.
		client_cert:             string           &optional;
		## Chain of certificates offered by the client to validate its
		## complete signing chain.
		client_cert_chain:       vector of string &optional;

		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id:      count            &optional;
	};
}

redef record connection += {
	ssl: Info &optional;
};

@load ./notary
@load ./main
@load ./mozilla-ca-list
