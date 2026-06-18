# @TEST-DOC: Test that FTP brute-force login sessions are logged and detected
# @TEST-EXEC: zeek -b -Cr $TRACES/ftp/bruteforce.pcap %INPUT
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: test ! -f reporter.log
@load base/protocols/conn
@load base/protocols/ftp
@load policy/protocols/ftp/detect-bruteforcing
