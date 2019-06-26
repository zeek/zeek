# @TEST-EXEC: zeek -C -r $TRACES/smb/dssetup_DsRoleGetPrimaryDomainInformation_standalone_workstation.cap %INPUT
# @TEST-EXEC: [ ! -f dce_rpc.log ]

@load base/protocols/smb

# The DCE_RPC analyzer is a little weird since it's instantiated
# by the SMB analyzer directly in some cases.  Care needs to be
# taken to handle a disabled analyzer correctly.
event zeek_init()
	{
	Analyzer::disable_analyzer(Analyzer::ANALYZER_DCE_RPC);
	}
