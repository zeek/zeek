# @TEST-DOC: Test for cleaning out tid_map when smb2_discarded_messages_state() is called
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb2-tree-id-state-exhaustion.pcap %INPUT >out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/smb

redef SMB::max_pending_messages = 100;

event smb2_discarded_messages_state(c: connection, request: string) &priority=10
	{
	print "smb2_discarded_messages_state before", request, |c$smb_state$tid_map|;
	}

event smb2_discarded_messages_state(c: connection, request: string) &priority=-10
	{
	print "smb2_discarded_messages_state after", request, |c$smb_state$tid_map|;
	}
