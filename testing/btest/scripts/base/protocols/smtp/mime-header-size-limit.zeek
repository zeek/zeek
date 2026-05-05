# @TEST-EXEC: zcat <$TRACES/smtp/mime-header-size-limit.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: zeek-cut -m history < conn.log > conn-history.log
# @TEST-EXEC: btest-diff conn-history.log

@load base/protocols/smtp
@load base/protocols/conn
