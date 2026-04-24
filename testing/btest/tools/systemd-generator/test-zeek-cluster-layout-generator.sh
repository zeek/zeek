# @TEST-DOC: Smoke test the zeek-cluster-layout-generator tool.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -o cluster-layout-default.zeek
# @TEST-EXEC: zeek ./cluster-layout-default.zeek
# @TEST-EXEC: btest-diff cluster-layout-default.zeek
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -L 3 -P 5 -W 7 -a 127.0.2.1 -b 10.0.0.1 -p 20000 -m 30000 -o cluster-layout-custom.zeek
# @TEST-EXEC: zeek ./cluster-layout-custom.zeek
# @TEST-EXEC: btest-diff cluster-layout-custom.zeek
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -L 3 -P 5 -W 'eth1:3 eth2:4' -a 127.0.2.1 -b 10.0.0.1 -p 20000 -m 30000 -o cluster-layout-tagged.zeek
# @TEST-EXEC: zeek ./cluster-layout-tagged.zeek
# @TEST-EXEC: btest-diff cluster-layout-tagged.zeek
#
# Classic Zeekctl worker-1-1, worker-2-1 style.
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -L 3 -P 5 -W '1:2 2:2' -a 127.0.2.1 -b 10.0.0.1 -o cluster-layout-zeekctl.zeek
# @TEST-EXEC: zeek ./cluster-layout-zeekctl.zeek
# @TEST-EXEC: btest-diff cluster-layout-zeekctl.zeek
