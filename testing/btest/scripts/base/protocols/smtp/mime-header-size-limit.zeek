# @TEST-EXEC: zcat <$TRACES/smtp/mime-header-size-limit.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff-cut -m history conn.log

@load base/protocols/smtp
@load base/protocols/conn

# Avoid log_string_field_truncated weird
redef Log::default_max_field_string_bytes = 0;
redef Log::default_max_total_string_bytes = 0;
