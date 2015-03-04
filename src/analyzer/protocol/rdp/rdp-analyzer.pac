%extern{
#include "ConvertUTF.h"
#include "file_analysis/Manager.h"
#include "types.bif.h"
%}

refine flow RDP_Flow += {

	function utf16_to_utf8_val(utf16: bytestring): StringVal
		%{
		size_t utf8size = 3 * utf16.length() + 1;
		char* utf8stringnative = new char[utf8size];
		const UTF16* sourcestart = reinterpret_cast<const UTF16*>(utf16.begin());
		const UTF16* sourceend = sourcestart + utf16.length();
		UTF8* targetstart = reinterpret_cast<UTF8*>(utf8stringnative);
		UTF8* targetend = targetstart + utf8size;

		ConversionResult res = ConvertUTF16toUTF8(&sourcestart, 
		                                          sourceend,
		                                          &targetstart, 
		                                          targetend, 
		                                          strictConversion);
		*targetstart = 0;

		if ( res != conversionOK )
			{
			connection()->bro_analyzer()->Weird("Failed UTF-16 to UTF-8 conversion");
			return new StringVal(utf16.length(), (const char *) utf16.begin());
			}

		// We're relying on no nulls being in the string.
		return new StringVal(utf8stringnative);
		%}

	function proc_rdp_client_request(client_request: Client_Request): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		BifEvent::generate_rdp_client_request(connection()->bro_analyzer(),
		                                      connection()->bro_analyzer()->Conn(),
		                                      bytestring_to_val(${client_request.cookie_value}));
		return true;
		%}

	function proc_rdp_result(gcc_response: GCC_Server_Create_Response): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		BifEvent::generate_rdp_result(connection()->bro_analyzer(),
		                              connection()->bro_analyzer()->Conn(),
		                              ${gcc_response.result});
		return true;
		%}


	function proc_rdp_client_core_data(ccore: Client_Core_Data): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

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
		return true;
		%}

	function proc_rdp_server_security(ssd: Server_Security_Data): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		BifEvent::generate_rdp_server_security(connection()->bro_analyzer(),
		                                       connection()->bro_analyzer()->Conn(),
		                                       ${ssd.encryption_method},
		                                       ${ssd.encryption_level});
		return true;
		%}

	function proc_x509_cert(x509: X509): bool
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

refine typeattr Client_Request += &let {
	proc: bool = $context.flow.proc_rdp_client_request(this);
};

refine typeattr Client_Core_Data += &let {
	proc: bool = $context.flow.proc_rdp_client_core_data(this);
};

refine typeattr GCC_Server_Create_Response += &let {
	proc: bool = $context.flow.proc_rdp_result(this);
};

refine typeattr Server_Security_Data += &let {
	proc: bool = $context.flow.proc_rdp_server_security(this);
};

refine typeattr X509 += &let {
	proc: bool = $context.flow.proc_x509_cert(this);
};
