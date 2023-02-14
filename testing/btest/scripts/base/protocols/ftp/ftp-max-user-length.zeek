# Test truncation of the user and password fields in the log.
# The password is "test", the user is "anonymous".
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv4.trace %INPUT
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::max_user_length = 4;
redef FTP::max_password_length = 2;
redef FTP::default_capture_password = T;
