# @TEST-EXEC: zeek -b -C -r $TRACES/smb/dssetup_DsRoleGetPrimaryDomainInformation_standalone_workstation.cap %INPUT
# @TEST-EXEC: btest-diff dce_rpc.log

@load base/protocols/dce-rpc
@load base/protocols/smb
