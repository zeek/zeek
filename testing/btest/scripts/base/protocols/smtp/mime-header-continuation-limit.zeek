# @TEST-EXEC: zcat <$TRACES/smtp/mime-folded-header-state-memory-exhaustion.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/smtp
@load base/protocols/conn
