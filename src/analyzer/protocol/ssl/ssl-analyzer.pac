# Analyzer for SSL (Bro-specific part).

%extern{
#include <vector>
#include <algorithm>
#include <iostream>
#include <iterator>

#include "util.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
%}


%header{
	class extract_certs {
	public:
		bytestring const& operator() (X509Certificate* cert) const
			{
			return cert->certificate();
			}
	};

	string orig_label(bool is_orig);
	void free_X509(void *);
	X509* d2i_X509_binpac(X509** px, const uint8** in, int len);
	string handshake_type_label(int type);
	%}

%code{
string orig_label(bool is_orig)
		{
		return string(is_orig ? "originator" :"responder");
		}

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

	string handshake_type_label(int type)
		{
		switch ( type ) {
		case HELLO_REQUEST: return string("HELLO_REQUEST");
		case CLIENT_HELLO: return string("CLIENT_HELLO");
		case SERVER_HELLO: return string("SERVER_HELLO");
		case SESSION_TICKET: return string("SESSION_TICKET");
		case CERTIFICATE: return string("CERTIFICATE");
		case SERVER_KEY_EXCHANGE: return string("SERVER_KEY_EXCHANGE");
		case CERTIFICATE_REQUEST: return string("CERTIFICATE_REQUEST");
		case SERVER_HELLO_DONE: return string("SERVER_HELLO_DONE");
		case CERTIFICATE_VERIFY: return string("CERTIFICATE_VERIFY");
		case CLIENT_KEY_EXCHANGE: return string("CLIENT_KEY_EXCHANGE");
		case FINISHED: return string("FINISHED");
		case CERTIFICATE_URL: return string("CERTIFICATE_URL");
		case CERTIFICATE_STATUS: return string("CERTIFICATE_STATUS");
		default: return string(fmt("UNKNOWN (%d)", type));
		}
		}

%}


function to_string_val(data : uint8[]) : StringVal
	%{
	char tmp[32];
	memset(tmp, 0, sizeof(tmp));

	// Just return an empty string if the string is longer than 32 bytes
	if ( data && data->size() <= 32 )
		{
		for ( unsigned int i = data->size(); i > 0; --i )
			tmp[i-1] = (*data)[i-1];
		}

	return new StringVal(32, tmp);
	%}

function version_ok(vers : uint16) : bool
	%{
	switch ( vers ) {
	case SSLv20:
	case SSLv30:
	case TLSv10:
	case TLSv11:
	case TLSv12:
		return true;

	default:
		return false;
	}
	%}

refine connection SSL_Conn += {

	%member{
		int eof;
	%}

	%init{
		eof=0;
	%}

	#%eof{
	#	if ( ! eof &&
	#	     state_ != STATE_CONN_ESTABLISHED &&
	#	     state_ != STATE_TRACK_LOST &&
	#	     state_ != STATE_INITIAL )
	#		bro_analyzer()->ProtocolViolation(fmt("unexpected end of connection in state %s",
	#			state_label(state_).c_str()));
	#	++eof;
	#%}

	%cleanup{
	%}

	function proc_change_cipher_spec(rec: SSLRecord) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ChangeCipherSpec from %s at state %s",
				orig_label(${rec.is_orig}).c_str(),
				state_label(old_state_).c_str()));
		return true;
		%}

	function proc_application_data(rec: SSLRecord) : bool
		%{
		if ( state_ != STATE_CONN_ESTABLISHED &&
		     (state_ != STATE_CLIENT_FINISHED && ! ${rec.is_orig}) )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ApplicationData from %s at state %s",
				orig_label(${rec.is_orig}).c_str(),
				state_label(old_state_).c_str()));
		return true;
		%}

	function proc_alert(rec: SSLRecord, level : int, desc : int) : bool
		%{
		BifEvent::generate_ssl_alert(bro_analyzer(), bro_analyzer()->Conn(),
						${rec.is_orig}, level, desc);
		return true;
		%}

	function proc_client_hello(rec: SSLRecord,
					version : uint16, ts : double,
					client_random : bytestring,
					session_id : uint8[],
					cipher_suites16 : uint16[],
					cipher_suites24 : uint24[]) : bool
		%{
		if ( ! version_ok(version) )
			bro_analyzer()->ProtocolViolation(fmt("unsupported client SSL version 0x%04x", version));
		else
			bro_analyzer()->ProtocolConfirmation();

		if ( ssl_client_hello )
			{
			vector<int>* cipher_suites = new vector<int>();
			if ( cipher_suites16 )
				std::copy(cipher_suites16->begin(), cipher_suites16->end(), std::back_inserter(*cipher_suites));
			else
				std::transform(cipher_suites24->begin(), cipher_suites24->end(), std::back_inserter(*cipher_suites), to_int());

			VectorVal* cipher_vec = new VectorVal(internal_type("index_vec")->AsVectorType());
			for ( unsigned int i = 0; i < cipher_suites->size(); ++i )
				{
				Val* ciph = new Val((*cipher_suites)[i], TYPE_COUNT);
				cipher_vec->Assign(i, ciph);
				}

			BifEvent::generate_ssl_client_hello(bro_analyzer(), bro_analyzer()->Conn(),
							version, ts, new StringVal(client_random.length(),
							(const char*) client_random.data()),
							to_string_val(session_id),
							cipher_vec);

			delete cipher_suites;
			}

		return true;
		%}

	function proc_server_hello(rec: SSLRecord,
					version : uint16, ts : double,
					server_random : bytestring,
					session_id : uint8[],
					cipher_suites16 : uint16[],
					cipher_suites24 : uint24[],
					comp_method : uint8) : bool
		%{
		if ( ! version_ok(version) )
			bro_analyzer()->ProtocolViolation(fmt("unsupported server SSL version 0x%04x", version));

		if ( ssl_server_hello )
			{
			vector<int>* ciphers = new vector<int>();

			if ( cipher_suites16 )
				std::copy(cipher_suites16->begin(), cipher_suites16->end(), std::back_inserter(*ciphers));
			else
				std::transform(cipher_suites24->begin(), cipher_suites24->end(), std::back_inserter(*ciphers), to_int());

			BifEvent::generate_ssl_server_hello(bro_analyzer(),
							bro_analyzer()->Conn(),
							version, ts, new StringVal(server_random.length(),
							(const char*) server_random.data()),
							to_string_val(session_id),
							ciphers->size()==0 ? 0 : ciphers->at(0), comp_method);

			delete ciphers;
			}

		return true;
		%}

	function proc_session_ticket_handshake(rec: SessionTicketHandshake, is_orig: bool): bool
		%{
		if ( ssl_session_ticket_handshake )
			{
			BifEvent::generate_ssl_session_ticket_handshake(bro_analyzer(),
							bro_analyzer()->Conn(),
							${rec.ticket_lifetime_hint},
							new StringVal(${rec.data}.length(), (const char*) ${rec.data}.data()));
			}
		return true;
		%}

	function proc_ssl_extension(rec: SSLRecord, type: int, data: bytestring) : bool
		%{
		if ( ssl_extension )
			BifEvent::generate_ssl_extension(bro_analyzer(),
						bro_analyzer()->Conn(), ${rec.is_orig}, type,
						new StringVal(data.length(), (const char*) data.data()));
		return true;
		%}

	function proc_certificate(rec: SSLRecord, certificates : bytestring[]) : bool
		%{
		if ( certificates->size() == 0 )
			return true;

		if ( x509_certificate )
			{
			STACK_OF(X509)* untrusted_certs = 0;

			for ( unsigned int i = 0; i < certificates->size(); ++i )
				{
				const bytestring& cert = (*certificates)[i];
				const uint8* data = cert.data();
				X509* pTemp = d2i_X509_binpac(NULL, &data, cert.length());
				if ( ! pTemp )
					{
					BifEvent::generate_x509_error(bro_analyzer(), bro_analyzer()->Conn(),
					                              ${rec.is_orig}, ERR_get_error());
					return false;
					}

				RecordVal* pX509Cert = new RecordVal(x509_type);
				char tmp[256];
				BIO *bio = BIO_new(BIO_s_mem());

				pX509Cert->Assign(0, new Val((uint64) X509_get_version(pTemp), TYPE_COUNT));
				i2a_ASN1_INTEGER(bio, X509_get_serialNumber(pTemp));
				int len = BIO_read(bio, &(*tmp), sizeof tmp);
				pX509Cert->Assign(1, new StringVal(len, tmp));

				X509_NAME_print_ex(bio, X509_get_subject_name(pTemp), 0, XN_FLAG_RFC2253);
				len = BIO_gets(bio, &(*tmp), sizeof tmp);
				pX509Cert->Assign(2, new StringVal(len, tmp));
				X509_NAME_print_ex(bio, X509_get_issuer_name(pTemp), 0, XN_FLAG_RFC2253);
				len = BIO_gets(bio, &(*tmp), sizeof tmp);
				pX509Cert->Assign(3, new StringVal(len, tmp));
				BIO_free(bio);

				pX509Cert->Assign(4, new Val(get_time_from_asn1(X509_get_notBefore(pTemp)), TYPE_TIME));
				pX509Cert->Assign(5, new Val(get_time_from_asn1(X509_get_notAfter(pTemp)), TYPE_TIME));
				StringVal* der_cert = new StringVal(cert.length(), (const char*) cert.data());

				BifEvent::generate_x509_certificate(bro_analyzer(), bro_analyzer()->Conn(),
							${rec.is_orig},
							pX509Cert,
							i, certificates->size(),
							der_cert);

				// Are there any X509 extensions?
				//printf("Number of x509 extensions: %d\n", X509_get_ext_count(pTemp));
				if ( x509_extension && X509_get_ext_count(pTemp) > 0 )
					{
					int num_ext = X509_get_ext_count(pTemp);
					for ( int k = 0; k < num_ext; ++k )
						{
						char name[256];
						char oid[256];

						memset(name, 0, sizeof(name));
						memset(oid, 0, sizeof(oid));

						X509_EXTENSION* ex = X509_get_ext(pTemp, k);

						if ( ! ex )
							continue;

						ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
						const char* short_name = OBJ_nid2sn(OBJ_obj2nid(ext_asn));

						OBJ_obj2txt(name, sizeof(name) - 1, ext_asn, 0);
						OBJ_obj2txt(oid, sizeof(oid) - 1, ext_asn, 1);

						int critical = 0;
						if ( X509_EXTENSION_get_critical(ex) != 0 )
							critical = 1;

						BIO *bio = BIO_new(BIO_s_mem());
						if( ! X509V3_EXT_print(bio, ex, 0, 0))
							M_ASN1_OCTET_STRING_print(bio, ex->value);

						BIO_flush(bio);
						int length = BIO_pending(bio);

						// Use OPENSSL_malloc here. Using new or anything else can lead
						// to interesting, hard to debug segfaults.
						char *buffer = (char*) OPENSSL_malloc(length);
						BIO_read(bio, buffer, length);
						StringVal* ext_val = new StringVal(length, buffer);
						OPENSSL_free(buffer);

						BIO_free_all(bio);

						RecordVal* pX509Ext = new RecordVal(x509_extension_type);
						pX509Ext->Assign(0, new StringVal(name));

						if ( short_name && strlen(short_name) > 0 )
							pX509Ext->Assign(1, new StringVal(short_name));

						pX509Ext->Assign(2, new StringVal(oid));
						pX509Ext->Assign(3, new Val(critical, TYPE_BOOL));
						pX509Ext->Assign(4, ext_val);

						BifEvent::generate_x509_extension(bro_analyzer(),
									bro_analyzer()->Conn(),
									${rec.is_orig},
									pX509Cert->Ref(),
									pX509Ext);
						}
					}

				X509_free(pTemp);
				}
			}
		return true;
		%}

	function proc_v2_certificate(rec: SSLRecord, cert : bytestring) : bool
		%{
		vector<bytestring>* cert_list = new vector<bytestring>(1,cert);
		bool ret = proc_certificate(rec, cert_list);
		delete cert_list;
		return ret;
		%}

	function proc_v3_certificate(rec: SSLRecord, cl : CertificateList) : bool
		%{
		vector<X509Certificate*>* certs = cl->val();
		vector<bytestring>* cert_list = new vector<bytestring>();

		std::transform(certs->begin(), certs->end(),
		std::back_inserter(*cert_list), extract_certs());

		bool ret = proc_certificate(rec, cert_list);
		delete cert_list;
		return ret;
		%}

	function proc_v2_client_master_key(rec: SSLRecord, cipher_kind: int) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected v2 client master key message from %s in state %s",
				orig_label(${rec.is_orig}).c_str(),
				state_label(old_state_).c_str()));

		BifEvent::generate_ssl_established(bro_analyzer(),
				bro_analyzer()->Conn());

		return true;
		%}

	function proc_unknown_handshake(hs: Handshake, is_orig: bool) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown handshake message (%d) from %s",
			${hs.msg_type}, orig_label(is_orig).c_str()));
		return true;
		%}

	function proc_handshake(hs: Handshake, is_orig: bool) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected Handshake message %s from %s in state %s",
				handshake_type_label(${hs.msg_type}).c_str(),
				orig_label(is_orig).c_str(),
				state_label(old_state_).c_str()));

		return true;
		%}

	function proc_unknown_record(rec: SSLRecord) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown SSL record type (%d) from %s",
				${rec.content_type},
				orig_label(${rec.is_orig}).c_str()));
		return true;
		%}

	function proc_ciphertext_record(rec : SSLRecord) : bool
		%{
		if ( state_ == STATE_TRACK_LOST )
			bro_analyzer()->ProtocolViolation(fmt("unexpected ciphertext record from %s in state %s",
				orig_label(${rec.is_orig}).c_str(),
				state_label(old_state_).c_str()));

		else if ( state_ == STATE_CONN_ESTABLISHED &&
		          old_state_ == STATE_COMM_ENCRYPTED )
			{
			BifEvent::generate_ssl_established(bro_analyzer(),
							bro_analyzer()->Conn());
			}

		return true;
		%}
};

refine typeattr ChangeCipherSpec += &let {
	proc : bool = $context.connection.proc_change_cipher_spec(rec)
		&requires(state_changed);
};

refine typeattr Alert += &let {
	proc : bool = $context.connection.proc_alert(rec, level, description);
};

refine typeattr V2Error += &let {
	proc : bool = $context.connection.proc_alert(rec, -1, error_code);
};

refine typeattr ApplicationData += &let {
	proc : bool = $context.connection.proc_application_data(rec);
};

refine typeattr ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(rec, client_version,
				gmt_unix_time, random_bytes,
				session_id, csuits, 0)
		&requires(state_changed);
};

refine typeattr V2ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(rec, client_version, 0,
				challenge, session_id, 0, ciphers)
		&requires(state_changed);
};

refine typeattr ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(rec, server_version,
			gmt_unix_time, random_bytes, session_id, cipher_suite, 0,
			compression_method)
		&requires(state_changed);
};

refine typeattr V2ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(rec, server_version, 0,
				conn_id_data, 0, 0, ciphers, 0)
		&requires(state_changed);

	cert : bool = $context.connection.proc_v2_certificate(rec, cert_data)
		&requires(proc);
};

refine typeattr Certificate += &let {
	proc : bool = $context.connection.proc_v3_certificate(rec, certificates)
		&requires(state_changed);
};

refine typeattr V2ClientMasterKey += &let {
	proc : bool = $context.connection.proc_v2_client_master_key(rec, cipher_kind)
		&requires(state_changed);
};

refine typeattr UnknownHandshake += &let {
	proc : bool = $context.connection.proc_unknown_handshake(hs, is_orig);
};

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(this, rec.is_orig);
};

refine typeattr SessionTicketHandshake += &let {
	proc : bool = $context.connection.proc_session_ticket_handshake(this, rec.is_orig);
}

refine typeattr UnknownRecord += &let {
	proc : bool = $context.connection.proc_unknown_record(rec);
};

refine typeattr CiphertextRecord += &let {
	proc : bool = $context.connection.proc_ciphertext_record(rec);
}

refine typeattr SSLExtension += &let {
	proc : bool = $context.connection.proc_ssl_extension(rec, type, data);
};
