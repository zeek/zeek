# @TEST-DOC: Check that usage of continuation for manager fails early and does not result in raising std::logic_error.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# @TEST-START-FILE config1
[zeek]
manager = 1
  proxies = 1
  loggers = 1

env =
  a=1
  b=2

base_dir = /opt/zeek

[interface lo]
interface = lo
  lol
workers = 1
# @TEST-END-FILE
