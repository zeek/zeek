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
			BifEvent::generate_ssl_session_ticket_handshake(bro_analyzer(),
							bro_analyzer()->Conn(),
							${rec.ticket_lifetime_hint},
							new StringVal(${rec.data}.length(), (const char*) ${rec.data}.data()));
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
			BifEvent::generate_ssl_extension(bro_analyzer(),
						bro_analyzer()->Conn(), ${rec.is_orig}, type,
						new StringVal(length, reinterpret_cast<const char*>(data)));
		return true;
		%}

	function proc_ec_point_formats(rec: HandshakeRecord, point_format_list: uint8[]) : bool
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

	function proc_elliptic_curves(rec: HandshakeRecord, list: uint16[]) : bool
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

	function proc_apnl(rec: HandshakeRecord, protocols: ProtocolName[]) : bool
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

	function proc_server_name(rec: HandshakeRecord, list: ServerName[]) : bool
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
		 if ( status_type == 1 ) // ocsp
			{
			BifEvent::generate_ssl_stapled_ocsp(bro_analyzer(),
							    bro_analyzer()->Conn(), ${rec.is_orig},
							    new StringVal(response.length(),
							    (const char*) response.data()));
			}

		return true;
		%}

	function proc_ec_server_key_exchange(rec: HandshakeRecord, curve_type: uint8, curve: uint16) : bool
		%{
		if ( curve_type == NAMED_CURVE )
			BifEvent::generate_ssl_server_curve(bro_analyzer(),
			  bro_analyzer()->Conn(), curve);

		return true;
		%}

	function proc_dh_server_key_exchange(rec: HandshakeRecord, p: bytestring, g: bytestring, Ys: bytestring) : bool
		%{
		BifEvent::generate_ssl_dh_server_params(bro_analyzer(),
			bro_analyzer()->Conn(),
		  new StringVal(p.length(), (const char*) p.data()),
		  new StringVal(g.length(), (const char*) g.data()),
		  new StringVal(Ys.length(), (const char*) Ys.data())
		  );

		return true;
		%}

	function proc_handshake(is_orig: bool, msg_type: uint8, length: uint24) : bool
		%{
		BifEvent::generate_ssl_handshake_message(bro_analyzer(),
			bro_analyzer()->Conn(), is_orig, msg_type, to_int()(length));

		return true;
		%}


};

refine typeattr ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(client_version,
				gmt_unix_time, random_bytes,
				session_id, csuits, 0);
};

refine typeattr ServerHello += &let {
	proc : bool = $context.connection.proc_server_hello(server_version,
			gmt_unix_time, random_bytes, session_id, cipher_suite, 0,
			compression_method);
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

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(rec.is_orig, rec.msg_type, rec.msg_length);
};

