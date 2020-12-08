# @TEST-EXEC: zeek -b -r $TRACES/smb/smb3_multichannel.pcap %INPUT
# @TEST-EXEC: btest-diff smb_files.log
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/smb


