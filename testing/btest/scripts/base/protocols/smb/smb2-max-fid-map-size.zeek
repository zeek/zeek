# @TEST-DOC: Test for capping SMB::State$fid_map at SMB::max_fid_map_size
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb2-fid-map-growth.pcap %INPUT >&2
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/smb

redef SMB::max_fid_map_size = 100;
