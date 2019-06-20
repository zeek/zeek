%extern{
#include "file_analysis/Manager.h"
#include "types.bif.h"
%}

refine flow RDP_Flow += {
	function proc_rdp_connect_request(cr: Connect_Request): bool
		%{
		if ( rdp_connect_request )
			{
			BifEvent::generate_rdp_connect_request(connection()->bro_analyzer(),
			                                       connection()->bro_analyzer()->Conn(),
			                                       bytestring_to_val(${cr.cookie_value}));
			}

		return true;
		%}

	function proc_rdp_negotiation_response(nr: RDP_Negotiation_Response): bool
		%{
		if ( rdp_negotiation_response )
			{
			BifEvent::generate_rdp_negotiation_response(connection()->bro_analyzer(),
			                                            connection()->bro_analyzer()->Conn(),
			                                            ${nr.selected_protocol});
			}

		return true;
		%}

	function proc_rdp_negotiation_failure(nf: RDP_Negotiation_Failure): bool
		%{
		if ( rdp_negotiation_failure )
			{
			BifEvent::generate_rdp_negotiation_failure(connection()->bro_analyzer(),
			                                           connection()->bro_analyzer()->Conn(),
			                                           ${nf.failure_code});
			}

		return true;
		%}


	function proc_rdp_gcc_server_create_response(gcc_response: GCC_Server_Create_Response): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( rdp_gcc_server_create_response )
			BifEvent::generate_rdp_gcc_server_create_response(connection()->bro_analyzer(),
			                                                  connection()->bro_analyzer()->Conn(),
			                                                  ${gcc_response.result});

		return true;
		%}


	function proc_rdp_client_core_data(ccore: Client_Core_Data): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( rdp_client_core_data )
			{
			RecordVal* ec_flags = new RecordVal(BifType::Record::RDP::EarlyCapabilityFlags);
			ec_flags->Assign(0, val_mgr->GetBool(${ccore.SUPPORT_ERRINFO_PDU}));
			ec_flags->Assign(1, val_mgr->GetBool(${ccore.WANT_32BPP_SESSION}));
			ec_flags->Assign(2, val_mgr->GetBool(${ccore.SUPPORT_STATUSINFO_PDU}));
			ec_flags->Assign(3, val_mgr->GetBool(${ccore.STRONG_ASYMMETRIC_KEYS}));
			ec_flags->Assign(4, val_mgr->GetBool(${ccore.SUPPORT_MONITOR_LAYOUT_PDU}));
			ec_flags->Assign(5, val_mgr->GetBool(${ccore.SUPPORT_NETCHAR_AUTODETECT}));
			ec_flags->Assign(6, val_mgr->GetBool(${ccore.SUPPORT_DYNVC_GFX_PROTOCOL}));
			ec_flags->Assign(7, val_mgr->GetBool(${ccore.SUPPORT_DYNAMIC_TIME_ZONE}));
			ec_flags->Assign(8, val_mgr->GetBool(${ccore.SUPPORT_HEARTBEAT_PDU}));

			RecordVal* ccd = new RecordVal(BifType::Record::RDP::ClientCoreData);
			ccd->Assign(0, val_mgr->GetCount(${ccore.version_major}));
			ccd->Assign(1, val_mgr->GetCount(${ccore.version_minor}));
			ccd->Assign(2, val_mgr->GetCount(${ccore.desktop_width}));
			ccd->Assign(3, val_mgr->GetCount(${ccore.desktop_height}));
			ccd->Assign(4, val_mgr->GetCount(${ccore.color_depth}));
			ccd->Assign(5, val_mgr->GetCount(${ccore.sas_sequence}));
			ccd->Assign(6, val_mgr->GetCount(${ccore.keyboard_layout}));
			ccd->Assign(7, val_mgr->GetCount(${ccore.client_build}));
			ccd->Assign(8, utf16_bytestring_to_utf8_val(connection()->bro_analyzer()->Conn(), ${ccore.client_name}));
			ccd->Assign(9, val_mgr->GetCount(${ccore.keyboard_type}));
			ccd->Assign(10, val_mgr->GetCount(${ccore.keyboard_sub}));
			ccd->Assign(11, val_mgr->GetCount(${ccore.keyboard_function_key}));
			ccd->Assign(12, utf16_bytestring_to_utf8_val(connection()->bro_analyzer()->Conn(), ${ccore.ime_file_name}));
			ccd->Assign(13, val_mgr->GetCount(${ccore.post_beta2_color_depth}));
			ccd->Assign(14, val_mgr->GetCount(${ccore.client_product_id}));
			ccd->Assign(15, val_mgr->GetCount(${ccore.serial_number}));
			ccd->Assign(16, val_mgr->GetCount(${ccore.high_color_depth}));
			ccd->Assign(17, val_mgr->GetCount(${ccore.supported_color_depths}));
			ccd->Assign(18, ec_flags);
			ccd->Assign(19, utf16_bytestring_to_utf8_val(connection()->bro_analyzer()->Conn(), ${ccore.dig_product_id}));

			BifEvent::generate_rdp_client_core_data(connection()->bro_analyzer(),
			                                        connection()->bro_analyzer()->Conn(),
			                                        ccd);
			}

		return true;
		%}

	function proc_rdp_client_security_data(csec: Client_Security_Data): bool
		%{
		if ( ! rdp_client_security_data )
			return false;

		RecordVal* csd = new RecordVal(BifType::Record::RDP::ClientSecurityData);
		csd->Assign(0, val_mgr->GetCount(${csec.encryption_methods}));
		csd->Assign(1, val_mgr->GetCount(${csec.ext_encryption_methods}));

		BifEvent::generate_rdp_client_security_data(connection()->bro_analyzer(),
		                                            connection()->bro_analyzer()->Conn(),
		                                            csd);
		return true;
		%}

	function proc_rdp_client_network_data(cnetwork: Client_Network_Data): bool
		%{
		if ( ! rdp_client_network_data )
			return false;

		if ( ${cnetwork.channel_def_array}->size() )
			{
			VectorVal* channels = new VectorVal(BifType::Vector::RDP::ClientChannelList);

			for ( uint i = 0; i < ${cnetwork.channel_def_array}->size(); ++i )
				{
				RecordVal* channel_def = new RecordVal(BifType::Record::RDP::ClientChannelDef);

				channel_def->Assign(0, bytestring_to_val(${cnetwork.channel_def_array[i].name}));
				channel_def->Assign(1, val_mgr->GetCount(${cnetwork.channel_def_array[i].options}));

				channel_def->Assign(2, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_INITIALIZED}));
				channel_def->Assign(3, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_RDP}));
				channel_def->Assign(4, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_SC}));
				channel_def->Assign(5, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_ENCRYPT_CS}));
				channel_def->Assign(6, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_HIGH}));
				channel_def->Assign(7, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_MED}));
				channel_def->Assign(8, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_PRI_LOW}));
				channel_def->Assign(9, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_COMPRESS_RDP}));
				channel_def->Assign(10, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_COMPRESS}));
				channel_def->Assign(11, val_mgr->GetBool(${cnetwork.channel_def_array[i].CHANNEL_OPTION_SHOW_PROTOCOL}));
				channel_def->Assign(12, val_mgr->GetBool(${cnetwork.channel_def_array[i].REMOTE_CONTROL_PERSISTENT}));

				channels->Assign(channels->Size(), channel_def);
				}

			BifEvent::generate_rdp_client_network_data(connection()->bro_analyzer(),
			                                           connection()->bro_analyzer()->Conn(),
			                                           channels);
			}

		return true;
		%}


        function proc_rdp_client_cluster_data(ccluster: Client_Cluster_Data): bool
                %{
                if ( ! rdp_client_cluster_data )
                        return false;

                RecordVal* ccld = new RecordVal(BifType::Record::RDP::ClientClusterData);
		ccld->Assign(0, val_mgr->GetCount(${ccluster.flags}));
		ccld->Assign(1, val_mgr->GetCount(${ccluster.redir_session_id}));
 		ccld->Assign(2, val_mgr->GetBool(${ccluster.REDIRECTION_SUPPORTED}));
 		ccld->Assign(3, val_mgr->GetCount(${ccluster.SERVER_SESSION_REDIRECTION_VERSION_MASK}));
 		ccld->Assign(4, val_mgr->GetCount(${ccluster.REDIRECTED_SESSIONID_FIELD_VALID}));
 		ccld->Assign(5, val_mgr->GetBool(${ccluster.REDIRECTED_SMARTCARD}));

                BifEvent::generate_rdp_client_cluster_data(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            ccld);
                return true;
                %}



	function proc_rdp_server_security(ssd: Server_Security_Data): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( rdp_server_security )
			BifEvent::generate_rdp_server_security(connection()->bro_analyzer(),
			                                       connection()->bro_analyzer()->Conn(),
			                                       ${ssd.encryption_method},
			                                       ${ssd.encryption_level});

		return true;
		%}

	function proc_rdp_server_certificate(cert: Server_Certificate): bool
		%{
		if ( rdp_server_certificate )
			{
			BifEvent::generate_rdp_server_certificate(connection()->bro_analyzer(),
			                                          connection()->bro_analyzer()->Conn(),
			                                          ${cert.cert_type},
			                                          ${cert.permanently_issued});
			}

		return true;
		%}

	function proc_x509_cert_data(x509: X509_Cert_Data): bool
		%{
		const bytestring& cert = ${x509.cert};

		ODesc file_handle;
		file_handle.AddRaw("Analyzer::ANALYZER_RDP");
		file_handle.Add(connection()->bro_analyzer()->Conn()->StartTime());
		connection()->bro_analyzer()->Conn()->IDString(&file_handle);
		string file_id = file_mgr->HashHandle(file_handle.Description());

		file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
		                 cert.length(),
		                 connection()->bro_analyzer()->GetAnalyzerTag(),
		                 connection()->bro_analyzer()->Conn(),
		                 false, // It seems there are only server certs?
		                 file_id, "application/x-x509-user-cert");
		file_mgr->EndOfFile(file_id);

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

