%extern{
#include "zeek/Desc.h"
#include "zeek/file_analysis/Manager.h"

#include "zeek/analyzer/protocol/rdp/types.bif.h"
%}

refine flow RDP_Flow += {
	function proc_rdp_connect_request(cr: Connect_Request): bool
		%{
		if ( rdp_connect_request )
			{
			zeek::BifEvent::enqueue_rdp_connect_request(connection()->zeek_analyzer(),
			                                      connection()->zeek_analyzer()->Conn(),
			                                      to_stringval(${cr.cookie_value}),
			                                      ${cr.rdp_neg_req} ? ${cr.rdp_neg_req.flags} : 0);
			}

		return true;
		%}

	function proc_rdp_negotiation_response(nr: RDP_Negotiation_Response): bool
		%{
		if ( rdp_negotiation_response )
			{
			zeek::BifEvent::enqueue_rdp_negotiation_response(connection()->zeek_analyzer(),
			                                           connection()->zeek_analyzer()->Conn(),
			                                           ${nr.selected_protocol},
			                                           ${nr.flags});
			}

		return true;
		%}

	function proc_rdp_negotiation_failure(nf: RDP_Negotiation_Failure): bool
		%{
		if ( rdp_negotiation_failure )
			{
			zeek::BifEvent::enqueue_rdp_negotiation_failure(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${nf.failure_code},
			                                          ${nf.flags});
			}

		return true;
		%}


	function proc_rdp_gcc_server_create_response(gcc_response: GCC_Server_Create_Response): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( rdp_gcc_server_create_response )
			zeek::BifEvent::enqueue_rdp_gcc_server_create_response(connection()->zeek_analyzer(),
			                                                 connection()->zeek_analyzer()->Conn(),
			                                                 ${gcc_response.result});

		return true;
		%}


	function proc_rdp_client_core_data(ccore: Client_Core_Data): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( rdp_client_core_data )
			{
			auto ec_flags = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RDP::EarlyCapabilityFlags);
			ec_flags->Assign(0, ${ccore.SUPPORT_ERRINFO_PDU});
			ec_flags->Assign(1, ${ccore.WANT_32BPP_SESSION});
			ec_flags->Assign(2, ${ccore.SUPPORT_STATUSINFO_PDU});
			ec_flags->Assign(3, ${ccore.STRONG_ASYMMETRIC_KEYS});
			ec_flags->Assign(4, ${ccore.SUPPORT_MONITOR_LAYOUT_PDU});
			ec_flags->Assign(5, ${ccore.SUPPORT_NETCHAR_AUTODETECT});
			ec_flags->Assign(6, ${ccore.SUPPORT_DYNVC_GFX_PROTOCOL});
			ec_flags->Assign(7, ${ccore.SUPPORT_DYNAMIC_TIME_ZONE});
			ec_flags->Assign(8, ${ccore.SUPPORT_HEARTBEAT_PDU});

			auto ccd = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RDP::ClientCoreData);
			ccd->Assign(0, ${ccore.version_major});
			ccd->Assign(1, ${ccore.version_minor});
			ccd->Assign(2, ${ccore.desktop_width});
			ccd->Assign(3, ${ccore.desktop_height});
			ccd->Assign(4, ${ccore.color_depth});
			ccd->Assign(5, ${ccore.sas_sequence});
			ccd->Assign(6, ${ccore.keyboard_layout});
			ccd->Assign(7, ${ccore.client_build});
			ccd->Assign(8, utf16_to_utf8_val(connection()->zeek_analyzer()->Conn(), ${ccore.client_name}));
			ccd->Assign(9, ${ccore.keyboard_type});
			ccd->Assign(10, ${ccore.keyboard_sub});
			ccd->Assign(11, ${ccore.keyboard_function_key});
			ccd->Assign(12, utf16_to_utf8_val(connection()->zeek_analyzer()->Conn(), ${ccore.ime_file_name}));
			ccd->Assign(13, ${ccore.post_beta2_color_depth});
			ccd->Assign(14, ${ccore.client_product_id});
			ccd->Assign(15, ${ccore.serial_number});
			ccd->Assign(16, ${ccore.high_color_depth});
			ccd->Assign(17, ${ccore.supported_color_depths});
			ccd->Assign(18, std::move(ec_flags));
			ccd->Assign(19, utf16_to_utf8_val(connection()->zeek_analyzer()->Conn(), ${ccore.dig_product_id}));

			zeek::BifEvent::enqueue_rdp_client_core_data(connection()->zeek_analyzer(),
			                                       connection()->zeek_analyzer()->Conn(),
			                                       std::move(ccd));
			}

		return true;
		%}

	function proc_rdp_client_security_data(csec: Client_Security_Data): bool
		%{
		if ( ! rdp_client_security_data )
			return false;

		auto csd = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RDP::ClientSecurityData);
		csd->Assign(0, ${csec.encryption_methods});
		csd->Assign(1, ${csec.ext_encryption_methods});

		zeek::BifEvent::enqueue_rdp_client_security_data(connection()->zeek_analyzer(),
		                                           connection()->zeek_analyzer()->Conn(),
		                                           std::move(csd));
		return true;
		%}

	function proc_rdp_client_network_data(cnetwork: Client_Network_Data): bool
		%{
		if ( ! rdp_client_network_data )
			return false;

		if ( ${cnetwork.channel_def_array}->size() )
			{
			auto channels = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::RDP::ClientChannelList);

			for ( uint i = 0; i < ${cnetwork.channel_def_array}->size(); ++i )
				{
				auto channel_def = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RDP::ClientChannelDef);

				channel_def->Assign(0, to_stringval(${cnetwork.channel_def_array[i].name}));
				channel_def->Assign(1, ${cnetwork.channel_def_array[i].options});

				channel_def->Assign(2, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_INITIALIZED});
				channel_def->Assign(3, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_RDP});
				channel_def->Assign(4, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_SC});
				channel_def->Assign(5, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_CS});
				channel_def->Assign(6, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_HIGH});
				channel_def->Assign(7, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_MED});
				channel_def->Assign(8, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_LOW});
				channel_def->Assign(9, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_COMPRESS_RDP});
				channel_def->Assign(10, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_COMPRESS});
				channel_def->Assign(11, ${cnetwork.channel_def_array[i].CHANNEL_OPTION_SHOW_PROTOCOL});
				channel_def->Assign(12, ${cnetwork.channel_def_array[i].REMOTE_CONTROL_PERSISTENT});

				channels->Assign(channels->Size(), std::move(channel_def));
				}

			zeek::BifEvent::enqueue_rdp_client_network_data(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          std::move(channels));
			}

		return true;
		%}

	function proc_rdp_client_cluster_data(ccluster: Client_Cluster_Data): bool
		%{
		if ( ! rdp_client_cluster_data )
			return false;

		auto ccld = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RDP::ClientClusterData);
		ccld->Assign(0, ${ccluster.flags});
		ccld->Assign(1, ${ccluster.redir_session_id});
		ccld->Assign(2, ${ccluster.REDIRECTION_SUPPORTED});
		ccld->Assign(3, ${ccluster.SERVER_SESSION_REDIRECTION_VERSION_MASK});
		ccld->Assign(4, ${ccluster.REDIRECTED_SESSIONID_FIELD_VALID});
		ccld->Assign(5, ${ccluster.REDIRECTED_SMARTCARD});

		zeek::BifEvent::enqueue_rdp_client_cluster_data(connection()->zeek_analyzer(),
		                                          connection()->zeek_analyzer()->Conn(),
		                                          std::move(ccld));
		return true;
		%}

	function proc_rdp_server_security(ssd: Server_Security_Data): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( rdp_server_security )
			zeek::BifEvent::enqueue_rdp_server_security(connection()->zeek_analyzer(),
			                                       connection()->zeek_analyzer()->Conn(),
			                                       ${ssd.encryption_method},
			                                       ${ssd.encryption_level});

		return true;
		%}

	function proc_rdp_server_certificate(cert: Server_Certificate): bool
		%{
		if ( rdp_server_certificate )
			{
			zeek::BifEvent::enqueue_rdp_server_certificate(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          ${cert.cert_type},
			                                          ${cert.permanently_issued});
			}

		return true;
		%}

	function proc_x509_cert_data(x509: X509_Cert_Data): bool
		%{
		const bytestring& cert = ${x509.cert};

		zeek::ODesc file_handle;
		file_handle.AddRaw("Analyzer::ANALYZER_RDP");
		file_handle.Add(connection()->zeek_analyzer()->Conn()->StartTime());
		connection()->zeek_analyzer()->Conn()->IDString(&file_handle);
		string file_id = zeek::file_mgr->HashHandle(file_handle.Description());

		zeek::file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
		                       cert.length(),
		                       connection()->zeek_analyzer()->GetAnalyzerTag(),
		                       connection()->zeek_analyzer()->Conn(),
		                       false, // It seems there are only server certs?
		                       file_id, "application/x-x509-user-cert");
		zeek::file_mgr->EndOfFile(file_id);

		return true;
		%}
};

refine typeattr Connect_Request += &let {
	proc: bool = $context.flow.proc_rdp_connect_request(this);
};

refine typeattr RDP_Negotiation_Response += &let {
	proc: bool = $context.flow.proc_rdp_negotiation_response(this);
};

refine typeattr RDP_Negotiation_Failure += &let {
	proc: bool = $context.flow.proc_rdp_negotiation_failure(this);
};

refine typeattr Client_Core_Data += &let {
	proc: bool = $context.flow.proc_rdp_client_core_data(this);
};

refine typeattr Client_Security_Data += &let {
        proc: bool = $context.flow.proc_rdp_client_security_data(this);
};

refine typeattr Client_Network_Data += &let {
	proc: bool = $context.flow.proc_rdp_client_network_data(this);
};

refine typeattr Client_Cluster_Data += &let {
        proc: bool = $context.flow.proc_rdp_client_cluster_data(this);
};

refine typeattr GCC_Server_Create_Response += &let {
	proc: bool = $context.flow.proc_rdp_gcc_server_create_response(this);
};

refine typeattr Server_Security_Data += &let {
	proc: bool = $context.flow.proc_rdp_server_security(this);
};

refine typeattr Server_Certificate += &let {
	proc: bool = $context.flow.proc_rdp_server_certificate(this);
};

refine typeattr X509_Cert_Data += &let {
	proc: bool = $context.flow.proc_x509_cert_data(this);
};
