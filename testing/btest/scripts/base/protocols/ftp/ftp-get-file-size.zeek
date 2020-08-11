# This tests extracting the server reported file size 
# from FTP sessions.
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ftp-with-numbers-in-filename.pcap %INPUT
# @TEST-EXEC: btest-diff ftp.log

@load base/protocols/ftp
