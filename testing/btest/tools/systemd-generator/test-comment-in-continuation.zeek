# @TEST-DOC: The comment in the continuation line would be part of args when indented, but it should not.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-systemd-generator
#
# @TEST-EXEC: mkdir dir1
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-systemd-generator --config config1 dir1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep ^ExecStart' btest-diff ./dir1/zeek-manager.service

# @TEST-START-FILE config1
[zeek]
manager = 1
loggers = 1
archiver = 0
args =
  script1
  # a comment why script2 is needed
  script2
# a comment why script3 is needed
  script3
       # a comment why script4 is needed
    script4

base_dir = /opt/zeek
# @TEST-END-FILE
