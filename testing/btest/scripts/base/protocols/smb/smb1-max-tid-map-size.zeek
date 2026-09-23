# @TEST-DOC: Test for capping SMB::State$tid_map at SMB::max_tid_map_size
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb1-tid-map-growth.pcap %INPUT >&2
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/smb

redef SMB::max_tid_map_size = 100;
