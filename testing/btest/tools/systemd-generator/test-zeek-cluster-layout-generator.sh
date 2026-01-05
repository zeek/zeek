# @TEST-DOC: Smoke test the zeek-cluster-layout-generator tool.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: mkdir normal-dir
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -o cluster-layout-default.zeek
# @TEST-EXEC: zeek ./cluster-layout-default.zeek
# @TEST-EXEC: btest-diff cluster-layout-default.zeek
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -L 3 -P 5 -W 7 -a 127.0.2.1 -b 10.0.0.1 -p 20000 -m 30000 -o cluster-layout-custom.zeek
# @TEST-EXEC: zeek ./cluster-layout-custom.zeek
# @TEST-EXEC: btest-diff cluster-layout-custom.zeek
