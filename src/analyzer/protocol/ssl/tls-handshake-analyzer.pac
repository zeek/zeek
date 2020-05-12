# Analyzer for SSL/TLS Handshake protocol (Bro-specific part).

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

refine connection Handshake_Conn += {

	%include proc-client-hello.pac
	%include proc-server-hello.pac
	%include proc-certificate.pac

	function proc_session_ticket_handshake(rec: SessionTicketHandshake, is_orig: bool): bool
		%{
		if ( ssl_session_ticket_handshake )
			{
			BifEvent::enqueue_ssl_session_ticket_handshake(bro_analyzer(),
							bro_analyzer()->Conn(),
							${rec.ticket_lifetime_hint},
							make_intrusive<StringVal>(${rec.data}.length(), (const char*) ${rec.data}.data()));
			}
		return true;
		%}

	function proc_ssl_extension(rec: HandshakeRecord, type: int, sourcedata: const_bytestring) : bool
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
			bro_analyzer()->ProtocolViolation(fmt("Impossible extension length: %zu", length));
			bro_analyzer()->SetSkip(true);
			return true;
			}

		length -= 4;
		const unsigned char* data = sourcedata.begin() + 4;

		if ( ssl_extension )
			BifEvent::enqueue_ssl_extension(bro_analyzer(),
						bro_analyzer()->Conn(), ${rec.is_orig}, type,
						make_intrusive<StringVal>(length, reinterpret_cast<const char*>(data)));
		return true;
		%}

	function proc_ec_point_formats(rec: HandshakeRecord, point_format_list: uint8[]) : bool
		%{
		if ( ! ssl_extension_ec_point_formats )
			return true;

		auto points = make_intrusive<VectorVal>(zeek::vars::index_vec);

		if ( point_format_list )
			{
			for ( unsigned int i = 0; i < point_format_list->size(); ++i )
				points->Assign(i, val_mgr->Count((*point_format_list)[i]));
			}

		BifEvent::enqueue_ssl_extension_ec_point_formats(bro_analyzer(), bro_analyzer()->Conn(),
		   ${rec.is_orig}, std::move(points));

		return true;
		%}

	function proc_elliptic_curves(rec: HandshakeRecord, list: uint16[]) : bool
		%{
		if ( ! ssl_extension_elliptic_curves )
			return true;

		auto curves = make_intrusive<VectorVal>(zeek::vars::index_vec);

		if ( list )
			{
			for ( unsigned int i = 0; i < list->size(); ++i )
				curves->Assign(i, val_mgr->Count((*list)[i]));
			}

		BifEvent::enqueue_ssl_extension_elliptic_curves(bro_analyzer(), bro_analyzer()->Conn(),
		   ${rec.is_orig}, std::move(curves));

		return true;
		%}

	function proc_client_key_share(rec: HandshakeRecord, keyshare: KeyShareEntry[]) : bool
		%{
		if ( ! ssl_extension_key_share )
			return true;

		auto nglist = make_intrusive<VectorVal>(zeek::vars::index_vec);

		if ( keyshare )
			{
			for ( unsigned int i = 0; i < keyshare->size(); ++i )
				nglist->Assign(i, val_mgr->Count((*keyshare)[i]->namedgroup()));
			}

		BifEvent::enqueue_ssl_extension_key_share(bro_analyzer(), bro_analyzer()->Conn(), ${rec.is_orig}, std::move(nglist));

		return true;
		%}

	function proc_server_key_share(rec: HandshakeRecord, keyshare: KeyShareEntry) : bool
		%{
		if ( ! ssl_extension_key_share )
			return true;

		auto nglist = make_intrusive<VectorVal>(zeek::vars::index_vec);

		nglist->Assign(0u, val_mgr->Count(keyshare->namedgroup()));
		BifEvent::enqueue_ssl_extension_key_share(bro_analyzer(), bro_analyzer()->Conn(), ${rec.is_orig}, std::move(nglist));
		return true;
		%}

	function proc_hello_retry_request_key_share(rec: HandshakeRecord, namedgroup: uint16) : bool
		%{
		if ( ! ssl_extension_key_share )
			return true;

		auto nglist = make_intrusive<VectorVal>(zeek::vars::index_vec);

		nglist->Assign(0u, val_mgr->Count(namedgroup));
		BifEvent::enqueue_ssl_extension_key_share(bro_analyzer(), bro_analyzer()->Conn(), ${rec.is_orig}, std::move(nglist));
		return true;
		%}

	function proc_signature_algorithm(rec: HandshakeRecord, supported_signature_algorithms: SignatureAndHashAlgorithm[]) : bool
		%{
		if ( ! ssl_extension_signature_algorithm )
			return true;

		auto slist = make_intrusive<VectorVal>(zeek::lookup_type<VectorType>("signature_and_hashalgorithm_vec"));

		if ( supported_signature_algorithms )
			{
			for ( unsigned int i = 0; i < supported_signature_algorithms->size(); ++i )
				{
				RecordVal* el = new RecordVal(BifType::Record::SSL::SignatureAndHashAlgorithm);
				el->Assign(0, val_mgr->Count((*supported_signature_algorithms)[i]->HashAlgorithm()));
				el->Assign(1, val_mgr->Count((*supported_signature_algorithms)[i]->SignatureAlgorithm()));
				slist->Assign(i, el);
				}
			}

		BifEvent::enqueue_ssl_extension_signature_algorithm(bro_analyzer(), bro_analyzer()->Conn(), ${rec.is_orig}, std::move(slist));

		return true;
		%}

	function proc_apnl(rec: HandshakeRecord, protocols: ProtocolName[]) : bool
		%{
		if ( ! ssl_extension_application_layer_protocol_negotiation )
			return true;

		auto plist = make_intrusive<VectorVal>(zeek::vars::string_vec);

		if ( protocols )
			{
			for ( unsigned int i = 0; i < protocols->size(); ++i )
				plist->Assign(i, make_intrusive<StringVal>((*protocols)[i]->name().length(), (const char*) (*protocols)[i]->name().data()));
			}

		BifEvent::enqueue_ssl_extension_application_layer_protocol_negotiation(bro_analyzer(), bro_analyzer()->Conn(),
											${rec.is_orig}, std::move(plist));

		return true;
		%}

	function proc_server_name(rec: HandshakeRecord, list: ServerName[]) : bool
		%{
		auto servers = make_intrusive<VectorVal>(zeek::vars::string_vec);

		if ( list )
			{
			for ( unsigned int i = 0, j = 0; i < list->size(); ++i )
				{
				ServerName* servername = (*list)[i];
				if ( servername->name_type() != 0 )
					{
					bro_analyzer()->Weird("ssl_ext_unknown_server_name_type", fmt("%d", servername->name_type()));
					continue;
					}

				if ( servername->host_name() )
					servers->Assign(j++, make_intrusive<StringVal>(servername->host_name()->host_name().length(), (const char*) servername->host_name()->host_name().data()));
				else
					bro_analyzer()->Weird("Empty server_name extension in ssl connection");
				}
			}

		if ( ssl_extension_server_name )
			BifEvent::enqueue_ssl_extension_server_name(bro_analyzer(), bro_analyzer()->Conn(),
		   	   ${rec.is_orig}, std::move(servers));

		return true;
		%}

	function proc_supported_versions(rec: HandshakeRecord, versions_list: uint16[]) : bool
		%{
		if ( ! ssl_extension_supported_versions )
			return true;

		auto versions = make_intrusive<VectorVal>(zeek::vars::index_vec);

		if ( versions_list )
			{
			for ( unsigned int i = 0; i < versions_list->size(); ++i )
				versions->Assign(i, val_mgr->Count((*versions_list)[i]));
			}

		BifEvent::enqueue_ssl_extension_supported_versions(bro_analyzer(), bro_analyzer()->Conn(),
			${rec.is_orig}, std::move(versions));

		return true;
		%}

	function proc_one_supported_version(rec: HandshakeRecord, version: uint16) : bool
		%{
		if ( ! ssl_extension_supported_versions )
			return true;

		auto versions = make_intrusive<VectorVal>(zeek::vars::index_vec);
		versions->Assign(0u, val_mgr->Count(version));

		BifEvent::enqueue_ssl_extension_supported_versions(bro_analyzer(), bro_analyzer()->Conn(),
			${rec.is_orig}, std::move(versions));

		return true;
		%}

	function proc_psk_key_exchange_modes(rec: HandshakeRecord, mode_list: uint8[]) : bool
		%{
		if ( ! ssl_extension_psk_key_exchange_modes )
			return true;

		auto modes = make_intrusive<VectorVal>(zeek::vars::index_vec);

		if ( mode_list )
			{
			for ( unsigned int i = 0; i < mode_list->size(); ++i )
				modes->Assign(i, val_mgr->Count((*mode_list)[i]));
			}

		BifEvent::enqueue_ssl_extension_psk_key_exchange_modes(bro_analyzer(), bro_analyzer()->Conn(),
			${rec.is_orig}, std::move(modes));

		return true;
		%}

	function proc_v3_certificate(is_orig: bool, cl : X509Certificate[]) : bool
		%{
		vector<X509Certificate*>* certs = cl;
		vector<bytestring>* cert_list = new vector<bytestring>();

		std::transform(certs->begin(), certs->end(),
		std::back_inserter(*cert_list), extract_certs());

		bool ret = proc_certificate(is_orig, cert_list);
		delete cert_list;
		return ret;
		%}

	function proc_unknown_handshake(hs: HandshakeRecord, is_orig: bool) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown handshake message (%d) from %s",
			${hs.msg_type}, orig_label(is_orig).c_str()));
		return true;
		%}

	function proc_certificate_status(rec : HandshakeRecord, status_type: uint8, response: bytestring) : bool
		%{
		ODesc common;
		common.AddRaw("Analyzer::ANALYZER_SSL");
		common.Add(bro_analyzer()->Conn()->StartTime());
		common.AddRaw("F");
		bro_analyzer()->Conn()->IDString(&common);

		if ( status_type == 1 && response.length() > 0 ) // ocsp
			{
			ODesc file_handle;
			file_handle.Add(common.Description());
			file_handle.Add("ocsp");

			string file_id = file_mgr->HashHandle(file_handle.Description());

			file_mgr->DataIn(reinterpret_cast<const u_char*>(response.data()),
			                 response.length(), bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), false, file_id, "application/ocsp-response");

			if ( ssl_stapled_ocsp )
				BifEvent::enqueue_ssl_stapled_ocsp(bro_analyzer(),
				        bro_analyzer()->Conn(),
				        ${rec.is_orig},
				        make_intrusive<StringVal>(response.length(), (const char*) response.data()));

			file_mgr->EndOfFile(file_id);
			}
		else if ( response.length() == 0 )
			{
			reporter->Weird(bro_analyzer()->Conn(), "SSL_zero_length_stapled_OCSP_message");
			}

		return true;
		%}

	function proc_ecdhe_server_key_exchange(kex: EcdheServerKeyExchange) : bool
		%{
		if ( ${kex.curve_type} != NAMED_CURVE )
			return true;

		if ( ssl_ecdh_server_params )
			BifEvent::enqueue_ssl_ecdh_server_params(bro_analyzer(),
			                                         bro_analyzer()->Conn(),
			                                         ${kex.params.curve},
			                                         make_intrusive<StringVal>(${kex.params.point}.length(), (const char*)${kex.params.point}.data()));

		if ( ssl_server_signature )
			{
			auto ha = make_intrusive<RecordVal>(BifType::Record::SSL::SignatureAndHashAlgorithm);

			if ( ${kex.signed_params.uses_signature_and_hashalgorithm} )
				{
				ha->Assign(0, val_mgr->Count(${kex.signed_params.algorithm.HashAlgorithm}));
				ha->Assign(1, val_mgr->Count(${kex.signed_params.algorithm.SignatureAlgorithm}));
				}
			else
				{
				// set to impossible value
				ha->Assign(0, val_mgr->Count(256));
				ha->Assign(1, val_mgr->Count(256));
				}

			BifEvent::enqueue_ssl_server_signature(bro_analyzer(),
			                                       bro_analyzer()->Conn(),
			                                       std::move(ha),
			                                       make_intrusive<StringVal>(${kex.signed_params.signature}.length(), (const char*)(${kex.signed_params.signature}).data()));
			}

		return true;
		%}

	function proc_ecdh_anon_server_key_exchange(kex: EcdhAnonServerKeyExchange) : bool
		%{
		if ( ${kex.curve_type} != NAMED_CURVE )
			return true;

		if ( ssl_ecdh_server_params )
			BifEvent::enqueue_ssl_ecdh_server_params(bro_analyzer(),
			                                         bro_analyzer()->Conn(),
			                                         ${kex.params.curve},
			                                         make_intrusive<StringVal>(${kex.params.point}.length(), (const char*)${kex.params.point}.data()));

		return true;
		%}

	function proc_rsa_client_key_exchange(rec: HandshakeRecord, rsa_pms: bytestring) : bool
		%{
		if ( ssl_rsa_client_pms )
			BifEvent::enqueue_ssl_rsa_client_pms(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     make_intrusive<StringVal>(rsa_pms.length(), (const char*)rsa_pms.data()));

		return true;
		%}

	function proc_dh_client_key_exchange(rec: HandshakeRecord, Yc: bytestring) : bool
		%{
		if ( ssl_dh_client_params )
			BifEvent::enqueue_ssl_dh_client_params(bro_analyzer(),
			                                       bro_analyzer()->Conn(),
			                                       make_intrusive<StringVal>(Yc.length(), (const char*)Yc.data()));

		return true;
		%}

	function proc_ecdh_client_key_exchange(rec: HandshakeRecord, point: bytestring) : bool
		%{
		if ( ssl_ecdh_client_params )
			BifEvent::enqueue_ssl_ecdh_client_params(bro_analyzer(),
			                                         bro_analyzer()->Conn(),
			                                         make_intrusive<StringVal>(point.length(), (const char*)point.data()));

		return true;
		%}

	function proc_signedcertificatetimestamp(rec: HandshakeRecord, version: uint8, logid: const_bytestring, timestamp: uint64, digitally_signed_algorithms: SignatureAndHashAlgorithm, digitally_signed_signature: const_bytestring) : bool
		%{
		if ( ! ssl_extension_signed_certificate_timestamp )
			return true;

		auto ha = make_intrusive<RecordVal>(BifType::Record::SSL::SignatureAndHashAlgorithm);
		ha->Assign(0, val_mgr->Count(digitally_signed_algorithms->HashAlgorithm()));
		ha->Assign(1, val_mgr->Count(digitally_signed_algorithms->SignatureAlgorithm()));

		BifEvent::enqueue_ssl_extension_signed_certificate_timestamp(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig},
			version,
			make_intrusive<StringVal>(logid.length(), reinterpret_cast<const char*>(logid.begin())),
			timestamp,
			std::move(ha),
			make_intrusive<StringVal>(digitally_signed_signature.length(), reinterpret_cast<const char*>(digitally_signed_signature.begin()))
		);

		return true;
		%}

	function proc_dhe_server_key_exchange(rec: HandshakeRecord, p: bytestring, g: bytestring, Ys: bytestring, signed_params: ServerKeyExchangeSignature) : bool
		%{
		if ( ssl_ecdh_server_params )
			BifEvent::enqueue_ssl_dh_server_params(bro_analyzer(),
			  bro_analyzer()->Conn(),
			  make_intrusive<StringVal>(p.length(), (const char*) p.data()),
			  make_intrusive<StringVal>(g.length(), (const char*) g.data()),
			  make_intrusive<StringVal>(Ys.length(), (const char*) Ys.data())
			  );

		if ( ssl_server_signature )
			{
			auto ha = make_intrusive<RecordVal>(BifType::Record::SSL::SignatureAndHashAlgorithm);

			if ( ${signed_params.uses_signature_and_hashalgorithm} )
				{
				ha->Assign(0, val_mgr->Count(${signed_params.algorithm.HashAlgorithm}));
				ha->Assign(1, val_mgr->Count(${signed_params.algorithm.SignatureAlgorithm}));
				}
				else
				{
				// set to impossible value
				ha->Assign(0, val_mgr->Count(256));
				ha->Assign(1, val_mgr->Count(256));
				}

			BifEvent::enqueue_ssl_server_signature(bro_analyzer(),
			  bro_analyzer()->Conn(), std::move(ha),
			  make_intrusive<StringVal>(${signed_params.signature}.length(), (const char*)(${signed_params.signature}).data())
			  );
			}

		return true;
		%}

	function proc_dh_anon_server_key_exchange(rec: HandshakeRecord, p: bytestring, g: bytestring, Ys: bytestring) : bool
		%{
		if ( ssl_dh_server_params )
			BifEvent::enqueue_ssl_dh_server_params(bro_analyzer(),
			  bro_analyzer()->Conn(),
			  make_intrusive<StringVal>(p.length(), (const char*) p.data()),
			  make_intrusive<StringVal>(g.length(), (const char*) g.data()),
			  make_intrusive<StringVal>(Ys.length(), (const char*) Ys.data())
			  );

		return true;
		%}

	function proc_handshake(is_orig: bool, msg_type: uint8, length: uint24) : bool
		%{
		if ( ssl_handshake_message )
			BifEvent::enqueue_ssl_handshake_message(bro_analyzer(),
				bro_analyzer()->Conn(), is_orig, msg_type, to_int()(length));

		return true;
		%}

	function proc_pre_shared_key_server_hello(rec: HandshakeRecord, identities: PSKIdentitiesList, binders: PSKBindersList) : bool
		%{
		if ( ! ssl_extension_pre_shared_key_server_hello )
			return true;

		auto slist = make_intrusive<VectorVal>(zeek::lookup_type<VectorType>("psk_identity_vec"));

		if ( identities && identities->identities() )
			{
			for ( auto&& identity : *(identities->identities()) )
				{
				RecordVal* el = new RecordVal(BifType::Record::SSL::PSKIdentity);
				el->Assign(0, make_intrusive<StringVal>(identity->identity().length(), (const char*) identity->identity().data()));
				el->Assign(1, val_mgr->Count(identity->obfuscated_ticket_age()));
				slist->Assign(slist->Size(), el);
				}
			}

		auto blist = make_intrusive<VectorVal>(zeek::vars::string_vec);

		if ( binders && binders->binders() )
			{
			for ( auto&& binder : *(binders->binders()) )
				blist->Assign(blist->Size(), make_intrusive<StringVal>(binder->binder().length(), (const char*) binder->binder().data()));
			}

		BifEvent::enqueue_ssl_extension_pre_shared_key_client_hello(bro_analyzer(), bro_analyzer()->Conn(),
			${rec.is_orig}, std::move(slist), std::move(blist));

		return true;
		%}

	function proc_pre_shared_key_client_hello(rec: HandshakeRecord, selected_identity: uint16) : bool
		%{
		if ( ! ssl_extension_pre_shared_key_client_hello )
			return true;

		BifEvent::enqueue_ssl_extension_pre_shared_key_server_hello(bro_analyzer(),
			bro_analyzer()->Conn(), ${rec.is_orig}, selected_identity);

		return true;
		%}

};

refine typeattr ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(client_version,
				gmt_unix_time, random_bytes,
				session_id, csuits, 0, cmeths);
};

refine typeattr ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(server_version,
			false, random_bytes, session_id, cipher_suite, 0,
			compression_method);
};

refine typeattr ServerHello13 += &let {
	proc : bool = $context.connection.proc_server_hello(server_version,
			false, random, 0, cipher_suite, 0,
			0);
};


refine typeattr Certificate += &let {
	proc : bool = $context.connection.proc_v3_certificate(rec.is_orig, certificates);
};

refine typeattr UnknownHandshake += &let {
	proc : bool = $context.connection.proc_unknown_handshake(hs, is_orig);
};

refine typeattr SessionTicketHandshake += &let {
	proc : bool = $context.connection.proc_session_ticket_handshake(this, rec.is_orig);
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

refine typeattr ServerHelloKeyShare += &let {
	proc : bool = $context.connection.proc_server_key_share(rec, keyshare);
};

refine typeattr HelloRetryRequestKeyShare += &let {
	proc : bool = $context.connection.proc_hello_retry_request_key_share(rec, namedgroup);
};

refine typeattr ClientHelloKeyShare += &let {
	proc : bool = $context.connection.proc_client_key_share(rec, keyshares);
};

refine typeattr SignatureAlgorithm += &let {
	proc : bool = $context.connection.proc_signature_algorithm(rec, supported_signature_algorithms);
}

refine typeattr ApplicationLayerProtocolNegotiationExtension += &let {
	proc : bool = $context.connection.proc_apnl(rec, protocol_name_list);
};

refine typeattr ServerNameExt += &let {
	proc : bool = $context.connection.proc_server_name(rec, server_names);
};

refine typeattr CertificateStatus += &let {
	proc : bool = $context.connection.proc_certificate_status(rec, status_type, response);
};

refine typeattr EcdheServerKeyExchange += &let {
	proc : bool = $context.connection.proc_ecdhe_server_key_exchange(this);
};

refine typeattr EcdhAnonServerKeyExchange += &let {
	proc : bool = $context.connection.proc_ecdh_anon_server_key_exchange(this);
};

refine typeattr DheServerKeyExchange += &let {
	proc : bool = $context.connection.proc_dhe_server_key_exchange(rec, dh_p, dh_g, dh_Ys, signed_params);
};

refine typeattr DhAnonServerKeyExchange += &let {
	proc : bool = $context.connection.proc_dh_anon_server_key_exchange(rec, dh_p, dh_g, dh_Ys);
};

refine typeattr RsaClientKeyExchange += &let {
	proc : bool = $context.connection.proc_rsa_client_key_exchange(rec, rsa_pms);
};

refine typeattr DhClientKeyExchange += &let {
	proc : bool = $context.connection.proc_dh_client_key_exchange(rec, dh_Yc);
};

refine typeattr EcdhClientKeyExchange += &let {
	proc : bool = $context.connection.proc_ecdh_client_key_exchange(rec, point);
};

refine typeattr SupportedVersions += &let {
	proc : bool = $context.connection.proc_supported_versions(rec, versions);
};

refine typeattr OneSupportedVersion += &let {
	proc : bool = $context.connection.proc_one_supported_version(rec, version);
};

refine typeattr PSKKeyExchangeModes += &let {
	proc : bool = $context.connection.proc_psk_key_exchange_modes(rec, modes);
};

refine typeattr OfferedPsks += &let {
	proc : bool = $context.connection.proc_pre_shared_key_server_hello(rec, identities, binders);
};

refine typeattr SelectedPreSharedKeyIdentity += &let {
	proc : bool = $context.connection.proc_pre_shared_key_client_hello(rec, selected_identity);
};

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(rec.is_orig, rec.msg_type, rec.msg_length);
};

refine typeattr SignedCertificateTimestamp += &let {
	proc : bool = $context.connection.proc_signedcertificatetimestamp(rec, version, logid, timestamp, digitally_signed_algorithms, digitally_signed_signature);
};
