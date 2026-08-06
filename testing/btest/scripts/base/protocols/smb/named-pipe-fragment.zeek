# @TEST-DOC: Ensure named-pipe delivery honors skip state (so it doesn't accumulate memory)
#
# @TEST-EXEC: zeek -br $TRACES/smb/fragment-state-exhaustion.pcap %INPUT >output
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/dce-rpc
@load base/protocols/smb
@load base/frameworks/notice/weird

redef Weird::weird_do_not_ignore_repeats += {
    "too_many_dce_rpc_msgs_in_reassembly"};

# Forces only one weird if skip is honored
# Many weirds fire if skip is not honored
redef DCE_RPC::max_cmd_reassembly = 24;
