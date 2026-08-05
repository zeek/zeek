# @TEST-DOC: Tests the limits on addresses in a single SMTP transaction.
# @TEST-EXEC: zcat < $TRACES/smtp/smtp-many-addresses.pcap.gz | zeek -b -r - %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/smtp
@load base/frameworks/notice/weird

redef SMTP::max_rcptto_addresses = 500;
redef SMTP::max_to_addresses = 500;
redef SMTP::max_cc_addresses = 500;
redef SMTP::max_path_length = 500;

event SMTP::log_smtp(rec: SMTP::Info)
	{
	print "end";
	print "rcptto", |rec$rcptto|;
	print "to", |rec$to|;
	print "cc", |rec$cc|;
	print "path", |rec$path|;
	}
