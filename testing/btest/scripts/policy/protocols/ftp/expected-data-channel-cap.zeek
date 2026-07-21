# @TEST-DOC: Verify FTP caps outstanding expected data-channel state created by repeated PORT commands.
#
# @TEST-EXEC: zcat < $TRACES/ftp/ftp-many-port-expected.pcap.gz | zeek -b -r - %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/protocols/ftp
@load base/frameworks/notice/weird

module FTP;

# PCAP contains 500 PORT commands. Limit to 499 and check for weird.
redef FTP::max_expected_data_channels = 499;

event zeek_done()
	{
	print fmt("ftp_data_expected_size=%d", |ftp_data_expected|);
	}
