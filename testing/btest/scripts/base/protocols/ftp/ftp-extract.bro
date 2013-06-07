# This tests FTP file extraction.
#
# @TEST-EXEC: bro -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: cat ftp-item-*.dat | sort > extractions
# @TEST-EXEC: btest-diff extractions

redef FTP::logged_commands += {"LIST"};
redef FTP::extract_file_types=/.*/;
