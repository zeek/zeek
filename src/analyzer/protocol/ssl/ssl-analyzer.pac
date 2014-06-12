# Analyzer for SSL (Bro-specific part).

%extern{
#include <vector>
#include <algorithm>
#include <iostream>
#include <iterator>

#include "util.h"

#include "file_analysis/Manager.h"
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
	string handshake_type_label(int type);
	%}

%code{
string orig_label(bool is_orig)
		{
		return string(is_orig ? "originator" :"responder");
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
		int established_;
	%}

	%init{
		established_ = false;
	%}

	%cleanup{
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

	function proc_ssl_extension(rec: SSLRecord, type: int, sourcedata: const_bytestring) : bool
		%{
		// We cheat a little bit here. We want to throw this event
		// for every extension we encounter, even those that are
		// handled by more specialized events later. To access the
		// parsed data, we use sourcedata, which contains the whole
		// data blob of the extension, including headers. We skip
		// over those (4 bytes).
		size_t length = sourcedata.length();
		if ( length < 4 )
			{
			// This should be impossible due to the binpac parser
			// and protocol description
			bro_analyzer()->ProtocolViolation(fmt("Impossible extension length: %lu", length));
			return true;
			}

		length -= 4;
		const unsigned char* data = sourcedata.begin() + 4;

		if ( ssl_extension )
			BifEvent::generate_ssl_extension(bro_analyzer(),
						bro_analyzer()->Conn(), ${rec.is_orig}, type,
						new StringVal(length, reinterpret_cast<const char*>(data)));
		return true;
		%}

	function proc_ec_point_formats(rec: SSLRecord, point_format_list: uint8[]) : bool
		%{
		VectorVal* points = new VectorVal(internal_type("index_vec")->AsVectorType());

		if ( point_format_list )
			{
			for ( unsigned int i = 0; i < point_format_list->size(); ++i )
				points->Assign(i, new Val((*point_format_list)[i], TYPE_COUNT));
			}

		BifEvent::generate_ssl_extension_ec_point_formats(bro_analyzer(), bro_analyzer()->Conn(),
		   ${rec.is_orig}, points);

		return true;
		%}

	function proc_elliptic_curves(rec: SSLRecord, list: uint16[]) : bool
		%{
		VectorVal* curves = new VectorVal(internal_type("index_vec")->AsVectorType());

		if ( list )
			{
			for ( unsigned int i = 0; i < list->size(); ++i )
				curves->Assign(i, new Val((*list)[i], TYPE_COUNT));
			}

		BifEvent::generate_ssl_extension_elliptic_curves(bro_analyzer(), bro_analyzer()->Conn(),
		   ${rec.is_orig}, curves);

		return true;
		%}

	function proc_apnl(rec: SSLRecord, protocols: ProtocolName[]) : bool
		%{
		VectorVal* plist = new VectorVal(internal_type("string_vec")->AsVectorType());

		if ( protocols )
			{
			for ( unsigned int i = 0; i < protocols->size(); ++i )
				plist->Assign(i, new StringVal((*protocols)[i]->name().length(), (const char*) (*protocols)[i]->name().data()));
			}

		BifEvent::generate_ssl_extension_application_layer_protocol_negotiation(bro_analyzer(), bro_analyzer()->Conn(),
											${rec.is_orig}, plist);

		return true;
		%}

	function proc_server_name(rec: SSLRecord, list: ServerName[]) : bool
		%{
		VectorVal* servers = new VectorVal(internal_type("string_vec")->AsVectorType());

		if ( list )
			{
			for ( unsigned int i = 0, j = 0; i < list->size(); ++i )
				{
				ServerName* servername = (*list)[i];
				if ( servername->name_type() != 0 )
					{
					bro_analyzer()->Weird(fmt("Encountered unknown type in server name ssl extension: %d", servername->name_type()));
					continue;
					}

				if ( servername->host_name() )
					servers->Assign(j++, new StringVal(servername->host_name()->host_name().length(), (const char*) servername->host_name()->host_name().data()));
				else
					bro_analyzer()->Weird("Empty server_name extension in ssl connection");
				}
			}

		BifEvent::generate_ssl_extension_server_name(bro_analyzer(), bro_analyzer()->Conn(),
		   ${rec.is_orig}, servers);

		return true;
		%}

	function proc_certificate(rec: SSLRecord, certificates : bytestring[]) : bool
		%{
		if ( certificates->size() == 0 )
			return true;

		ODesc common;
		common.AddRaw("Analyzer::ANALYZER_SSL");
		common.Add(bro_analyzer()->Conn()->StartTime());
		common.AddRaw(${rec.is_orig} ? "T" : "F", 1);
		bro_analyzer()->Conn()->IDString(&common);

		for ( unsigned int i = 0; i < certificates->size(); ++i )
			{
			const bytestring& cert = (*certificates)[i];

			ODesc file_handle;
			file_handle.Add(common.Description());
			file_handle.Add(i);

			string file_id = file_mgr->HashHandle(file_handle.Description());

			file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
			                 cert.length(), bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), ${rec.is_orig}, file_id);
			file_mgr->EndOfFile(file_id);
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

	function proc_v3_certificate(rec: SSLRecord, cl : X509Certificate[]) : bool
		%{
		vector<X509Certificate*>* certs = cl;
		vector<bytestring>* cert_list = new vector<bytestring>();

		std::transform(certs->begin(), certs->end(),
		std::back_inserter(*cert_list), extract_certs());

		bool ret = proc_certificate(rec, cert_list);
		delete cert_list;
		return ret;
		%}

	function proc_v2_client_master_key(rec: SSLRecord, cipher_kind: int) : bool
		%{
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

	function proc_unknown_record(rec: SSLRecord) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown SSL record type (%d) from %s",
				${rec.content_type},
				orig_label(${rec.is_orig}).c_str()));
		return true;
		%}

	function proc_ciphertext_record(rec : SSLRecord) : bool
		%{
		 if ( client_state_ == STATE_ENCRYPTED &&
		      server_state_ == STATE_ENCRYPTED &&
		      established_ == false )
			{
			established_ = true;
			BifEvent::generate_ssl_established(bro_analyzer(),
							bro_analyzer()->Conn());
			}

		BifEvent::generate_ssl_encrypted_data(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig}, ${rec.content_type}, ${rec.length});

		return true;
		%}

	function proc_heartbeat(rec : SSLRecord, type: uint8, payload_length: uint16, data: bytestring) : bool
		%{
		BifEvent::generate_ssl_heartbeat(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig}, ${rec.length}, type, payload_length,
			new StringVal(data.length(), (const char*) data.data()));
		return true;
		%}

	function proc_check_v2_server_hello_version(version: uint16) : bool
		%{
		if ( version != SSLv20 )
			bro_analyzer()->ProtocolViolation(fmt("Invalid version in SSL server hello. Version: %d", version));

		return true;
		%}

	function proc_certificate_status(rec : SSLRecord, status_type: uint8, response: bytestring) : bool
		%{
		 if ( status_type == 1 ) // ocsp
			{
			BifEvent::generate_ssl_stapled_ocsp(bro_analyzer(),
							    bro_analyzer()->Conn(), ${rec.is_orig},
							    new StringVal(response.length(),
							    (const char*) response.data()));
			}

		return true;
		%}

	function proc_ec_server_key_exchange(rec: SSLRecord, curve_type: uint8, curve: uint16) : bool
		%{
		if ( curve_type == NAMED_CURVE )
			BifEvent::generate_ssl_server_curve(bro_analyzer(),
			  bro_analyzer()->Conn(), curve);

		return true;
		%}

	function proc_dh_server_key_exchange(rec: SSLRecord, p: bytestring, g: bytestring, Ys: bytestring) : bool
		%{
		BifEvent::generate_ssl_dh_server_params(bro_analyzer(),
			bro_analyzer()->Conn(),
		  new StringVal(p.length(), (const char*) p.data()),
		  new StringVal(g.length(), (const char*) g.data()),
		  new StringVal(Ys.length(), (const char*) Ys.data())
		  );

		return true;
		%}

	function proc_ccs(rec: SSLRecord) : bool
		%{
		BifEvent::generate_ssl_change_cipher_spec(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig});

		return true;
		%}

	function proc_handshake(rec: SSLRecord, msg_type: uint8, length: uint24) : bool
		%{
		BifEvent::generate_ssl_handshake_message(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig}, msg_type, to_int()(length));

		return true;
		%}

};

refine typeattr Alert += &let {
	proc : bool = $context.connection.proc_alert(rec, level, description);
};

refine typeattr V2Error += &let {
	proc : bool = $context.connection.proc_alert(rec, -1, error_code);
};

refine typeattr Heartbeat += &let {
	proc : bool = $context.connection.proc_heartbeat(rec, type, payload_length, data);
};

refine typeattr ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(rec, client_version,
				gmt_unix_time, random_bytes,
				session_id, csuits, 0);
};

refine typeattr V2ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(rec, client_version, 0,
				challenge, session_id, 0, ciphers);
};

refine typeattr ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(rec, server_version,
			gmt_unix_time, random_bytes, session_id, cipher_suite, 0,
			compression_method);
};

refine typeattr V2ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(rec, server_version, 0,
				conn_id_data, 0, 0, ciphers, 0);

	check_v2 : bool = $context.connection.proc_check_v2_server_hello_version(server_version);

	cert : bool = $context.connection.proc_v2_certificate(rec, cert_data)
		&requires(proc);
};

refine typeattr Certificate += &let {
	proc : bool = $context.connection.proc_v3_certificate(rec, certificates);
};

refine typeattr V2ClientMasterKey += &let {
	proc : bool = $context.connection.proc_v2_client_master_key(rec, cipher_kind);
};

refine typeattr UnknownHandshake += &let {
	proc : bool = $context.connection.proc_unknown_handshake(hs, is_orig);
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
	proc : bool = $context.connection.proc_ssl_extension(rec, type, sourcedata);
};

refine typeattr EcPointFormats += &let {
	proc : bool = $context.connection.proc_ec_point_formats(rec, point_format_list);
};

refine typeattr EllipticCurves += &let {
	proc : bool = $context.connection.proc_elliptic_curves(rec, elliptic_curve_list);
};

refine typeattr ApplicationLayerProtocolNegotiationExtension += &let {
	proc : bool = $context.connection.proc_apnl(rec, protocol_name_list);
};

refine typeattr ServerNameExt += &let {
	proc : bool = $context.connection.proc_server_name(rec, server_names);
};

refine typeattr CertificateStatus += &let {
	proc : bool = $context.connection.proc_certificate_status(rec, status_type, response);
};

refine typeattr EcServerKeyExchange += &let {
	proc : bool = $context.connection.proc_ec_server_key_exchange(rec, curve_type, curve);
};

refine typeattr DhServerKeyExchange += &let {
	proc : bool = $context.connection.proc_dh_server_key_exchange(rec, dh_p, dh_g, dh_Ys);
};

refine typeattr ChangeCipherSpec += &let {
	proc : bool = $context.connection.proc_ccs(rec);
};

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(rec, msg_type, length);
};
