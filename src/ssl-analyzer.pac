# $Id:$

# Analyzer for SSL (Bro-specific part).

%extern{
#include <vector>
#include <algorithm>
#include <iostream>
#include <iterator>

#include "util.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "X509.h"
%}


%header{
	class extract_certs {
	public:
		bytestring const& operator() (X509Certificate* cert) const
			{
			return cert->certificate();
			}
	};

	void free_X509(void *);
	X509* d2i_X509_binpac(X509** px, const uint8** in, int len);
	%}

%code{
	void free_X509(void* cert)
		{
		X509_free((X509*) cert);
		}

	X509* d2i_X509_binpac(X509** px, const uint8** in, int len)
		{
#ifdef OPENSSL_D2I_X509_USES_CONST_CHAR
		return d2i_X509(px, in, len);
#else
		return d2i_X509(px, (u_char**) in, len);
#endif
		}
%}


function to_table_val(data : uint8[]) : TableVal
	%{
	TableVal* tv = new TableVal(SSL_sessionID);
	for ( unsigned int i = 0; i < data->size(); i += 4 )
		{
		uint32 temp = 0;
		for ( unsigned int j = 0; j < 4; ++j )
		if ( i + j < data->size() )
			temp |= (*data)[i + j] << (24 - 8 * j);

		Val* idx = new Val(i / 4, TYPE_COUNT);
		tv->Assign(idx, new Val((*data)[i], TYPE_COUNT));
		Unref(idx);
		}

	return tv;
	%}

function version_ok(vers : uint16) : bool
	%{
	switch ( vers ) {
	case SSLv20:
	case SSLv30:
	case TLSv10:
	case TLSv11:
		return true;

	default:
		return false;
	}
	%}

function convert_ciphers_uint24(ciph : uint24[]) : int[]
	%{
	vector<int>* newciph = new vector<int>();

	std::transform(ciph->begin(), ciph->end(),
	std::back_inserter(*newciph), to_int());

	return newciph;
	%}

function convert_ciphers_uint16(ciph : uint16[]) : int[]
	%{
	vector<int>* newciph = new vector<int>();

	std::copy(ciph->begin(), ciph->end(),
	std::back_inserter(*newciph));

	return newciph;
	%}

refine analyzer SSLAnalyzer += {
	%member{
		Analyzer* bro_analyzer_;

		vector<uint8>* client_session_id_;
		vector<int>* advertised_ciphers_;
		int version_;
		int cipher_;
	%}

	%init{
		bro_analyzer_ = 0;

		client_session_id_ = 0;
		advertised_ciphers_ = new vector<int>;
		version_ = -1;
		cipher_ = -1;

		if ( ! X509_Cert::bInited )
			X509_Cert::init();
	%}

	%eof{
		if ( state_ != STATE_CONN_ESTABLISHED &&
		     state_ != STATE_TRACK_LOST && state_ != STATE_INITIAL )
			bro_analyzer()->ProtocolViolation(fmt("unexpected end of connection in state %s",
				state_label(state_).c_str()));
	%}

	%cleanup{
		delete client_session_id_;
		client_session_id_ = 0;

		delete advertised_ciphers_;
		advertised_ciphers_ = 0;
	%}

	function bro_analyzer() : Analyzer
		%{
		return bro_analyzer_;
		%}

	function set_bro_analyzer(a : Analyzer) : void
		%{
		bro_analyzer_ = a;
		%}

	function check_cipher(cipher : int) : bool
		%{
		if ( ! ssl_compare_cipherspecs )
			return true;

		if ( std::find(advertised_ciphers_->begin(),
				advertised_ciphers_->end(), cipher) ==
		     advertised_ciphers_->end() )
			{
			bro_analyzer()->ProtocolViolation("chosen cipher not advertised before");
			return false;
			}

		return true;
		%}

	function certificate_error(err_num : int) : void
		%{
		StringVal* err_str =
			new StringVal(X509_verify_cert_error_string(err_num));
		bro_event_ssl_X509_error(bro_analyzer_, bro_analyzer_->Conn(),
						err_num, err_str);
		%}

	function proc_change_cipher_spec(msg : ChangeCipherSpec) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ChangeCipherSpec from %s at state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));
		return true;
		%}

	function proc_application_data(msg : ApplicationData) : bool
		%{
		if ( state_ != STATE_CONN_ESTABLISHED )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ApplicationData from %s at state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));
		return true;
		%}

	function proc_alert(level : int, description : int) : bool
		%{
		bro_event_ssl_conn_alert(bro_analyzer_, bro_analyzer_->Conn(),
						current_record_version_, level,
						description);
		return true;
		%}

	function proc_client_hello(version : uint16, session_id : uint8[],
					csuits : int[]) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected client hello message from %s in state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));

		if ( ! version_ok(version) )
			bro_analyzer()->ProtocolViolation(fmt("unsupported client SSL version 0x%04x", version));

		delete client_session_id_;
		client_session_id_ = new vector<uint8>(*session_id);

		TableVal* cipher_table = new TableVal(cipher_suites_list);
		for ( unsigned int i = 0; i < csuits->size(); ++i )
			{
			Val* ciph = new Val((*csuits)[i], TYPE_COUNT);
			cipher_table->Assign(ciph, 0);
			Unref(ciph);
			}

		bro_event_ssl_conn_attempt(bro_analyzer_, bro_analyzer_->Conn(),
						version, cipher_table);

		if ( ssl_compare_cipherspecs )
			{
			delete advertised_ciphers_;
			advertised_ciphers_ = csuits;
			}
		else
			delete csuits;

		return true;
		%}

	function proc_server_hello(version : uint16, session_id : uint8[],
				ciphers : int[], v2_sess_hit : int) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected server hello message from %s in state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));

		if ( ! version_ok(version) )
			bro_analyzer()->ProtocolViolation(fmt("unsupported server SSL version 0x%04x", version));

		version_ = version;

		TableVal* chosen_ciphers = new TableVal(cipher_suites_list);
		for ( unsigned int i = 0; i < ciphers->size(); ++i )
			{
			Val* ciph = new Val((*ciphers)[i], TYPE_COUNT);
			chosen_ciphers->Assign(ciph, 0);
			Unref(ciph);
			}

		bro_event_ssl_conn_server_reply(bro_analyzer_,
						bro_analyzer_->Conn(),
						version_, chosen_ciphers);

		if ( v2_sess_hit < 0 )
			{ // this is SSLv3
			cipher_ = (*ciphers)[0];
			check_cipher(cipher_);
			TableVal* tv = to_table_val(session_id);
			if ( client_session_id_ &&
			     *client_session_id_ == *session_id )
				bro_event_ssl_conn_reused(bro_analyzer_,
						bro_analyzer_->Conn(), tv);
			else
				bro_event_ssl_session_insertion(bro_analyzer_,
						bro_analyzer_->Conn(), tv);

			delete ciphers;
			}

		else if ( v2_sess_hit > 0 )
			{ // this is SSLv2 and a session hit
			if ( client_session_id_ )
				{
				TableVal* tv = to_table_val(client_session_id_);
				bro_event_ssl_conn_reused(bro_analyzer_,
						bro_analyzer_->Conn(), tv);
				}

			// We don't know the chosen cipher, as there is
			// no session storage.
			bro_event_ssl_conn_established(bro_analyzer_,
							bro_analyzer_->Conn(),
							version_, 0xffffffff);
			delete ciphers;
			}

		else
			{
			// This is SSLv2; we have to set advertised
			// ciphers to server ciphers.
			if ( ssl_compare_cipherspecs )
				{
				delete advertised_ciphers_;
				advertised_ciphers_ = ciphers;
				}
			}

		bro_analyzer()->ProtocolConfirmation();
		return true;
		%}

	function proc_certificate(certificates : bytestring[]) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected certificate message from %s in state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));

		if ( ! ssl_analyze_certificates )
			return true;
		if ( certificates->size() == 0 )
			return true;

		bro_event_ssl_certificate_seen(bro_analyzer_,
						bro_analyzer_->Conn(),
						! current_record_is_orig_);

		const bytestring& cert = (*certificates)[0];
		const uint8* data = cert.data();

		X509* pCert = d2i_X509_binpac(NULL, &data, cert.length());
		if ( ! pCert )
			{
			// X509_V_UNABLE_TO_DECRYPT_CERT_SIGNATURE
			certificate_error(4);
			return false;
			}

		RecordVal* pX509Cert = new RecordVal(x509_type);

		char tmp[256];
		X509_NAME_oneline(X509_get_issuer_name(pCert), tmp, sizeof tmp);
		pX509Cert->Assign(0, new StringVal(tmp));
		X509_NAME_oneline(X509_get_subject_name(pCert), tmp, sizeof tmp);

		pX509Cert->Assign(1, new StringVal(tmp));
		pX509Cert->Assign(2, new AddrVal(bro_analyzer_->Conn()->OrigAddr()));

		bro_event_ssl_certificate(bro_analyzer_, bro_analyzer_->Conn(),
					pX509Cert, current_record_is_orig_);

		if ( X509_get_ext_count(pCert) > 0 )
			{
			TableVal* x509ex = new TableVal(x509_extension);

			for ( int k = 0; k < X509_get_ext_count(pCert); ++k )
				{
				X509_EXTENSION* ex = X509_get_ext(pCert, k);
				ASN1_OBJECT* obj = X509_EXTENSION_get_object(ex);

				char buf[256];
				i2t_ASN1_OBJECT(buf, sizeof(buf), obj);
				Val* index = new Val(k+1, TYPE_COUNT);
				Val* value = new StringVal(strlen(buf), buf);
				x509ex->Assign(index, value);
				Unref(index);
				}

			bro_event_process_X509_extensions(bro_analyzer_,
						bro_analyzer_->Conn(), x509ex);
			}

		if ( ssl_verify_certificates )
			{
			STACK_OF(X509)* untrusted_certs = 0;
			if ( certificates->size() > 1 )
				{
				untrusted_certs = sk_X509_new_null();
				if ( ! untrusted_certs )
					{
					// X509_V_ERR_OUT_OF_MEM;
					certificate_error(17);
					return false;
					}

				for ( unsigned int i = 1;
				      i < certificates->size(); ++i )
					{
					const bytestring& temp =
						(*certificates)[i];
					const uint8* tdata = temp.data();
					X509* pTemp = d2i_X509_binpac(NULL,
							&tdata, temp.length());
					if ( ! pTemp )
						{
						// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
						certificate_error(2);
						return false;
						}

					sk_X509_push(untrusted_certs, pTemp);
					}
				}

			X509_STORE_CTX csc;
			X509_STORE_CTX_init(&csc, X509_Cert::ctx,
						pCert, untrusted_certs);
			X509_STORE_CTX_set_time(&csc, 0, time_t(network_time()));
			if (! X509_verify_cert(&csc))
				certificate_error(csc.error);
			X509_STORE_CTX_cleanup(&csc);

			sk_X509_pop_free(untrusted_certs, X509_free);
			}

		X509_free(pCert);
	return true;
		%}

	function proc_v2_certificate(cert : bytestring) : bool
		%{
		vector<bytestring>* cert_list = new vector<bytestring>(1,cert);
		bool ret = proc_certificate(cert_list);
		delete cert_list;
		return ret;
		%}

	function proc_v3_certificate(cl : CertificateList) : bool
		%{
		vector<X509Certificate*>* certs = cl->val();
		vector<bytestring>* cert_list = new vector<bytestring>();

		std::transform(certs->begin(), certs->end(),
		std::back_inserter(*cert_list), extract_certs());

		bool ret = proc_certificate(cert_list);
		delete cert_list;

		return ret;
		%}

	function proc_v2_client_master_key(cipher : int) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected v2 client master key message from %s in state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));

		check_cipher(cipher);
		bro_event_ssl_conn_established(bro_analyzer_,
				bro_analyzer_->Conn(), version_, cipher);

		return true;
		%}

	function proc_unknown_handshake(msg_type : int) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown handshake message (%d) from %s",
			msg_type, orig_label(current_record_is_orig_).c_str()));
		return true;
		%}

	function proc_handshake(msg : Handshake) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected Handshake message %s from %s in state %s",
				handshake_type_label(msg->msg_type()).c_str(),
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));
		return true;
		%}

	function proc_unknown_record(msg : UnknownRecord) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown SSL record type (%d) from %s",
				current_record_type_,
				orig_label(current_record_is_orig_).c_str()));
		return true;
		%}

	function proc_ciphertext_record(msg : CiphertextRecord) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ciphertext record from %s in state %s",
				orig_label(current_record_is_orig_).c_str(),
				state_label(old_state_).c_str()));

		if ( state_ == STATE_CONN_ESTABLISHED &&
		     old_state_ == STATE_COMM_ENCRYPTED )
			{
			bro_event_ssl_conn_established(bro_analyzer_,
							bro_analyzer_->Conn(),
							version_, cipher_);
			}

		return true;
		%}

};

refine typeattr ChangeCipherSpec += &let {
	proc : bool = $context.analyzer.proc_change_cipher_spec(this)
		&requires(state_changed);
};

refine typeattr Alert += &let {
	proc : bool = $context.analyzer.proc_alert(level, description);
};

refine typeattr V2Error += &let {
	proc : bool = $context.analyzer.proc_alert(-1, error_code);
};

refine typeattr ApplicationData += &let {
	proc : bool = $context.analyzer.proc_application_data(this);
};

refine typeattr ClientHello += &let {
	proc : bool = $context.analyzer.proc_client_hello(client_version,
				session_id, convert_ciphers_uint16(csuits))
		&requires(state_changed);
};

refine typeattr V2ClientHello += &let {
	proc : bool = $context.analyzer.proc_client_hello(client_version,
				session_id, convert_ciphers_uint24(ciphers))
		&requires(state_changed);
};

refine typeattr ServerHello += &let {
	proc : bool = $context.analyzer.proc_server_hello(server_version,
			session_id, convert_ciphers_uint16(cipher_suite), -1)
		&requires(state_changed);
};

refine typeattr V2ServerHello += &let {
	proc : bool = $context.analyzer.proc_server_hello(server_version, 0,
				convert_ciphers_uint24(ciphers), session_id_hit)
		&requires(state_changed);

	cert : bool = $context.analyzer.proc_v2_certificate(cert_data)
		&requires(proc);
};

refine typeattr Certificate += &let {
	proc : bool = $context.analyzer.proc_v3_certificate(certificates)
		&requires(state_changed);
};

refine typeattr V2ClientMasterKey += &let {
	proc : bool = $context.analyzer.proc_v2_client_master_key(to_int()(cipher_kind))
		&requires(state_changed);
};

refine typeattr UnknownHandshake += &let {
	proc : bool = $context.analyzer.proc_unknown_handshake(msg_type);
};

refine typeattr Handshake += &let {
	proc : bool = $context.analyzer.proc_handshake(this);
};

refine typeattr UnknownRecord += &let {
	proc : bool = $context.analyzer.proc_unknown_record(this);
};

refine typeattr CiphertextRecord += &let {
	proc : bool = $context.analyzer.proc_ciphertext_record(this)
		&requires(state_changed);
};
