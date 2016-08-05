%extern{
#include "ConvertUTF.h"
#include "file_analysis/Manager.h"
#include "types.bif.h"
%}

refine flow RDP_Flow += {

	function utf16_to_utf8_val(utf16: bytestring): StringVal
		%{
		std::string resultstring;

		size_t utf8size = (3 * utf16.length() + 1);

		if ( utf8size > resultstring.max_size() )
			{
			connection()->bro_analyzer()->Weird("excessive_utf16_length");
			return new StringVal("");
			}

		resultstring.resize(utf8size, '\0');

		// We can't assume that the string data is properly aligned
		// here, so make a copy.
		UTF16 utf16_copy[utf16.length()]; // Twice as much memory than necessary.
		memcpy(utf16_copy, utf16.begin(), utf16.length());

		const char* utf16_copy_end = reinterpret_cast<const char*>(utf16_copy) + utf16.length();
		const UTF16* sourcestart = utf16_copy;
		const UTF16* sourceend = reinterpret_cast<const UTF16*>(utf16_copy_end);

		UTF8* targetstart = reinterpret_cast<UTF8*>(&resultstring[0]);
		UTF8* targetend = targetstart + utf8size;

		ConversionResult res = ConvertUTF16toUTF8(&sourcestart,
		                                          sourceend,
		                                          &targetstart,
		                                          targetend,
		                                          lenientConversion);
		if ( res != conversionOK )
			{
			connection()->bro_analyzer()->Weird("Failed UTF-16 to UTF-8 conversion");
			return new StringVal(utf16.length(), (const char *) utf16.begin());
			}

		*targetstart = 0;

		// We're relying on no nulls being in the string.
		return new StringVal(resultstring.c_str());
		%}

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
			ec_flags->Assign(0, new Val(${ccore.SUPPORT_ERRINFO_PDU}, TYPE_BOOL));
			ec_flags->Assign(1, new Val(${ccore.WANT_32BPP_SESSION}, TYPE_BOOL));
			ec_flags->Assign(2, new Val(${ccore.SUPPORT_STATUSINFO_PDU}, TYPE_BOOL));
			ec_flags->Assign(3, new Val(${ccore.STRONG_ASYMMETRIC_KEYS}, TYPE_BOOL));
			ec_flags->Assign(4, new Val(${ccore.SUPPORT_MONITOR_LAYOUT_PDU}, TYPE_BOOL));
			ec_flags->Assign(5, new Val(${ccore.SUPPORT_NETCHAR_AUTODETECT}, TYPE_BOOL));
			ec_flags->Assign(6, new Val(${ccore.SUPPORT_DYNVC_GFX_PROTOCOL}, TYPE_BOOL));
			ec_flags->Assign(7, new Val(${ccore.SUPPORT_DYNAMIC_TIME_ZONE}, TYPE_BOOL));
			ec_flags->Assign(8, new Val(${ccore.SUPPORT_HEARTBEAT_PDU}, TYPE_BOOL));

			RecordVal* ccd = new RecordVal(BifType::Record::RDP::ClientCoreData);
			ccd->Assign(0, new Val(${ccore.version_major}, TYPE_COUNT));
			ccd->Assign(1, new Val(${ccore.version_minor}, TYPE_COUNT));
			ccd->Assign(2, new Val(${ccore.desktop_width}, TYPE_COUNT));
			ccd->Assign(3, new Val(${ccore.desktop_height}, TYPE_COUNT));
			ccd->Assign(4, new Val(${ccore.color_depth}, TYPE_COUNT));
			ccd->Assign(5, new Val(${ccore.sas_sequence}, TYPE_COUNT));
			ccd->Assign(6, new Val(${ccore.keyboard_layout}, TYPE_COUNT));
			ccd->Assign(7, new Val(${ccore.client_build}, TYPE_COUNT));
			ccd->Assign(8, utf16_to_utf8_val(${ccore.client_name}));
			ccd->Assign(9, new Val(${ccore.keyboard_type}, TYPE_COUNT));
			ccd->Assign(10, new Val(${ccore.keyboard_sub}, TYPE_COUNT));
			ccd->Assign(11, new Val(${ccore.keyboard_function_key}, TYPE_COUNT));
			ccd->Assign(12, utf16_to_utf8_val(${ccore.ime_file_name}));
			ccd->Assign(13, new Val(${ccore.post_beta2_color_depth}, TYPE_COUNT));
			ccd->Assign(14, new Val(${ccore.client_product_id}, TYPE_COUNT));
			ccd->Assign(15, new Val(${ccore.serial_number}, TYPE_COUNT));
			ccd->Assign(16, new Val(${ccore.high_color_depth}, TYPE_COUNT));
			ccd->Assign(17, new Val(${ccore.supported_color_depths}, TYPE_COUNT));
			ccd->Assign(18, ec_flags);
			ccd->Assign(19, utf16_to_utf8_val(${ccore.dig_product_id}));

			BifEvent::generate_rdp_client_core_data(connection()->bro_analyzer(),
			                                        connection()->bro_analyzer()->Conn(),
			                                        ccd);
			}

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
		                 file_id);
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
