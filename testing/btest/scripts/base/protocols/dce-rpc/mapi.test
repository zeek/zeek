# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/mapi.pcap %INPUT
# @TEST-EXEC: btest-diff dce_rpc.log
# @TEST-EXEC: btest-diff ntlm.log

@load base/protocols/dce-rpc
@load base/protocols/ntlm
