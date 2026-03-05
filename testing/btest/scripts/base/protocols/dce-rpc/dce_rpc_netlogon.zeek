# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/dce_rpc_netlogon.pcapng %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff dce_rpc.log

@load base/protocols/dce-rpc
@load base/protocols/ntlm
@load base/frameworks/notice/weird
