# Don't run for C++ scripts because there's no script to compile.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -C -r $TRACES/smb/smb2.delete-on-close-perms-delete-existing.pcap policy/protocols/smb/log-cmds
# @TEST-EXEC: btest-diff smb_files.log
# @TEST-EXEC: btest-diff smb_cmd.log

@load base/protocols/smb

redef SMB::logged_file_actions += { SMB::FILE_READ, SMB::FILE_WRITE };

