# @TEST-EXEC: zeek -C -r $TRACES/smb/smb2readwrite.pcap %INPUT
# @TEST-EXEC: btest-diff smb_files.log
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: test ! -f analyzer_failed.log

@load base/protocols/smb

redef SMB::logged_file_actions += { SMB::FILE_READ, SMB::FILE_WRITE };

