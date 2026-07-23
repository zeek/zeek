# @TEST-DOC: Test using a custom archiver command.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
# @TEST-EXEC: find dir1 | sort > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-abspath btest-diff ./dir1/zeek-archiver.service

# @TEST-START-FILE config1
env =
  LD_PRELOAD=/usr/local/lib/libjemalloc.so

interface = eth0

archiver = /usr/bin/my-archiver
archiver_args =
  my
  custom
  args
  -d
archiver_env =
  I_AM_ARCHIVER=1

base_dir = /opt/zeek
# @TEST-END-FILE
