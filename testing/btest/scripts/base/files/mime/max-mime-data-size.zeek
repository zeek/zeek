# @TEST-DOC: Test the MIME::max_mime_entity_data_size and MIME::max_mime_all_data_size limits
#
# @TEST-EXEC: zeek -b -f 'tcp port 25' -r $TRACES/smtp.pcap base/protocols/conn base/protocols/smtp %INPUT >out
# @TEST-EXEC: btest-diff-cut -m uid history service conn.log
# @TEST-EXEC: btest-diff out
@load ./common

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

redef MIME::max_mime_entity_data_size = 1024;

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

redef MIME::max_mime_all_data_size = 1024;

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

redef MIME::max_mime_entity_data_size = 64;
redef MIME::max_mime_all_data_size = 32;

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-NEXT
@load ./common

# These limits are such that with the given PCAP, two SubmitData()
# invocation would reach the selected limits directly. The first
# revision of the patch didn't raise weirds for this edge case.
redef MIME::max_mime_entity_data_size = 7;
redef MIME::max_mime_all_data_size = 77;

event mime_entity_data(c: connection, length: count, data: string)
	{
	print "mime_entity_data", c$uid, length, |data|, data[:16];
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	print "mime_all_data", c$uid, length, |data|, data[:16];
	}

# @TEST-START-FILE common.zeek
event conn_weird(name: string, c: connection, addl: string)
	{
	print "conn_weird", c$uid, name, addl;
	}
# @TEST-END-FILE
