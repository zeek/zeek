# @TEST-DOC: Check that an errno string is included in the error message if -o is used and the file can't be opened. Tries to a) write to a directory and b) use a file as part of a directory path.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: mkdir out
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -o out
# @TEST-EXEC: rmdir out && touch out
# @TEST-EXEC-FAIL: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -o out/cluster-layout.zeek
# @TEST-EXEC: test ! -f out/cluster-layout.zeek
# @TEST-EXEC: btest-diff .stderr
