# This tests FTP file extraction.
#
# @TEST-EXEC: bro -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff ftp-item-Rqjkzoroau4-0.dat
# @TEST-EXEC: btest-diff ftp-item-BTsa70Ua9x7-1.dat
# @TEST-EXEC: btest-diff ftp-item-VLQvJybrm38-2.dat
# @TEST-EXEC: btest-diff ftp-item-zrfwSs9K1yk-3.dat

redef FTP::logged_commands += {"LIST"};
redef FTP::extract_file_types=/.*/;
