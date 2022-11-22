# @TEST-DOC: Artificially generated pcap with FTP commands of length > 100. Verify generation of the involved logs.
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/fake-long-commands.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ftp.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
@load base/protocols/ftp

redef FTP::logged_commands += { "USER", "SYST" };
