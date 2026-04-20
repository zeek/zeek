# @TEST-DOC: Invoke zeek-systemd-generator with three directories at once.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir normal-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 normal-dir early-dir late-dir
# @TEST-EXEC: find normal-dir | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

# @TEST-START-FILE config1
interface = af_packet::eth0
workers = 1
manager = 1
proxies = 1
loggers = 1
# @TEST-END-FILE
