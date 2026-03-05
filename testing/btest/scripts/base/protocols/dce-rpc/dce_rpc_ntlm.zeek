# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/dce_rpc_ntlm.pcapng %INPUT
# @TEST-EXEC: btest-diff ntlm.log

@load base/protocols/dce-rpc
@load base/protocols/ntlm
