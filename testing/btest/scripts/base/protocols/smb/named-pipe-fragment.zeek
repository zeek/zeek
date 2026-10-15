# @TEST-DOC: Test named-pipe delivery to DCE-RPC analyzer exceeding max_cmd_reassembly.
#
# @TEST-EXEC: zeek -br $TRACES/smb/fragment-state-exhaustion.pcap %INPUT >output
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dce-rpc
@load base/protocols/smb
@load base/frameworks/notice/weird

# Record multiple weird in the weird.log. By default will only have the first.
redef Weird::weird_do_not_ignore_repeats += {
    "too_many_dce_rpc_msgs_in_reassembly"};

# Change the default a bit.
redef DCE_RPC::max_cmd_reassembly = 24;
