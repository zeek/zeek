# @TEST-EXEC: zcat <$TRACES/smtp/mime-header-size-limit.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/smtp
@load base/protocols/conn

# Disable continuation limit for this test.
redef MIME::max_header_continuation_lines = 0;
