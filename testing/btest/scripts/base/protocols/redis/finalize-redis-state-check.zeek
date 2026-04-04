# @TEST-DOC: Tests that the state check in the finalize_redis() hook functions correctly.
# @TEST-EXEC: zeek -r $TRACES/redis/oss-fuzz-473580107.pcap
# @TEST-EXEC: btest-diff .stderr
