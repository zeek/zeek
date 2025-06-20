# @TEST-DOC: Startup a ZeroMQ cluster using ::1 as address, but disable ZeroMQ's IPv6 support. Check the error messages. Relates to #4586.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: can-listen-tcp 6 ::1
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager  "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../common.zeek"
# @TEST-EXEC: btest-bg-run logger   "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger zeek -b ../common.zeek"
# @TEST-EXEC-FAIL: btest-bg-wait -k 10
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -E 's,^error: ZeroMQ: Failed to bind ([^ ]+) socket tcp://\[::1\]:[0-9]+:.*$,error: ZeroMQ: Failed to bind \1 socket...,g' | $SCRIPTS/diff-remove-abspath" btest-diff manager/.stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -E 's,^error: ZeroMQ: Failed to bind ([^ ]+) socket tcp://\[::1\]:[0-9]+:.*$,error: ZeroMQ: Failed to bind \1 socket...,g' | $SCRIPTS/diff-remove-abspath" btest-diff logger/.stderr

# @TEST-START-FILE common.zeek
@load frameworks/cluster/backend/zeromq
# Explicitly disable ipv6 support to provoke errors.
redef Cluster::Backend::ZeroMQ::ipv6 = F;
@load ./zeromq-test-bootstrap
# @TEST-END-FILE
