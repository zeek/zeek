# This tests FTP file extraction.
#
# @TEST-EXEC: bro -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: mv ftp-item-*-0.dat ftp-item-0.dat
# @TEST-EXEC: mv ftp-item-*-1.dat ftp-item-1.dat
# @TEST-EXEC: mv ftp-item-*-2.dat ftp-item-2.dat
# @TEST-EXEC: mv ftp-item-*-3.dat ftp-item-3.dat
# @TEST-EXEC: btest-diff ftp-item-0.dat
# @TEST-EXEC: btest-diff ftp-item-1.dat
# @TEST-EXEC: btest-diff ftp-item-2.dat
# @TEST-EXEC: btest-diff ftp-item-3.dat

redef FTP::logged_commands += {"LIST"};
redef FTP::extract_file_types=/.*/;
