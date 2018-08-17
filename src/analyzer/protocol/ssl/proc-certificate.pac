	function proc_certificate(is_orig: bool, certificates : bytestring[]) : bool
		%{
		if ( certificates->size() == 0 )
			return true;

		ODesc common;
		common.AddRaw("Analyzer::ANALYZER_SSL");
		common.Add(bro_analyzer()->Conn()->StartTime());
		common.AddRaw(is_orig ? "T" : "F", 1);
		bro_analyzer()->Conn()->IDString(&common);

		static const string user_mime = "application/x-x509-user-cert";
		static const string ca_mime = "application/x-x509-ca-cert";

		for ( unsigned int i = 0; i < certificates->size(); ++i )
			{
			const bytestring& cert = (*certificates)[i];

			ODesc file_handle;
			file_handle.Add(common.Description());
			file_handle.Add(i);

			string file_id = file_mgr->HashHandle(file_handle.Description());

			file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
			                 cert.length(), bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), is_orig, file_id, i == 0 ? user_mime : ca_mime);
			file_mgr->EndOfFile(file_id);
			}
		return true;
		%}


