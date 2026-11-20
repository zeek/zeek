# @TEST-DOC: The manager = 1 line is recognized as an invalid continuation line due to the blank line.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# @TEST-START-FILE config1
[zeek]
args =
  a
  b

  manager = 1

proxies = 1
loggers = 1

base_dir = /opt/zeek

[interface lo]
interface = lo
workers = 1
# @TEST-END-FILE
