# @TEST-EXEC: zeek -b -r $TRACES/smtp-mail-transactions-invalid.pcap %INPUT
# @TEST-EXEC: btest-diff smtp.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/smtp
