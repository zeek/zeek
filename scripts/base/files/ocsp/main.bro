@load base/frameworks/files
@load base/utils/paths

module FileOCSP;

export {
	## add one more argument to indicate is ocsp response or request
	redef record Files::AnalyzerArgs += {
		ocsp_type: string &optional;
	};
}
