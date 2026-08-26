# @TEST-DOC: Tests that repeated TCP reassembly involving block overlaps doesn't cause a stack overflow
# @TEST-EXEC: zcat <$TRACES/tcp/reassembly-overlap.pcap.gz | zeek -b -r -
