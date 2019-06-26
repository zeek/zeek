# This tests extracting the server reported file size 
# from FTP sessions.
#
# @TEST-EXEC: zeek -r $TRACES/ftp/ftp-with-numbers-in-filename.pcap
# @TEST-EXEC: btest-diff ftp.log
