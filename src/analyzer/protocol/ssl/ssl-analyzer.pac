# Analyzer for SSL (Bro-specific part).

refine connection SSL_Conn += {

	%include proc-client-hello.pac
	%include proc-server-hello.pac
	%include proc-certificate.pac

	function proc_v2_certificate(is_orig: bool, cert : bytestring) : bool
		%{
		vector<bytestring>* cert_list = new vector<bytestring>(1,cert);
		bool ret = proc_certificate(is_orig, cert_list);
		delete cert_list;
		return ret;
		%}


	function proc_v2_client_master_key(rec: SSLRecord, cipher_kind: int) : bool
		%{
		BifEvent::generate_ssl_established(bro_analyzer(),
				bro_analyzer()->Conn());

		return true;
		%}

	function proc_handshake(rec: SSLRecord, data: bytestring, is_orig: bool) : bool
		%{
		bro_analyzer()->SendHandshake(data.begin(), data.end(), is_orig);
		return true;
		%}
};


refine typeattr V2Error += &let {
	proc : bool = $context.connection.proc_alert(rec, -1, error_code);
};


refine typeattr V2ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(client_version, 0,
				challenge, session_id, 0, ciphers);
};

refine typeattr V2ServerHello += &let {
	check_v2 : bool = $context.connection.proc_check_v2_server_hello_version(server_version);

	proc : bool = $context.connection.proc_server_hello(server_version, 0,
				conn_id_data, 0, 0, ciphers, 0) &requires(check_v2) &if(check_v2 == true);

	cert : bool = $context.connection.proc_v2_certificate(rec.is_orig, cert_data)
		&requires(proc) &requires(check_v2) &if(check_v2 == true);
};

refine typeattr V2ClientMasterKey += &let {
	proc : bool = $context.connection.proc_v2_client_master_key(rec, cipher_kind);
};

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(rec, data, rec.is_orig);
};
