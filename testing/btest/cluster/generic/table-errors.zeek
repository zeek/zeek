# @TEST-DOC: When running with ZeroMQ, table &backend=Broker::MEMORY or &broker_store="teststore" should fail hard because they will be non-functional.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: BROKER_MANAGER_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC-FAIL: CLUSTER_NODE=manager zeek ./zeromq-test-bootstrap %INPUT 2>zeromq.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeromq.err
#
# No errors with Broker, only deprecation warnings.
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
# @TEST-EXEC: CLUSTER_NODE=manager zeek frameworks/cluster/backend/broker %INPUT 2>broker.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff broker.err

redef Log::default_rotation_interval = 0sec;

module Test;

global tbl1: table[string] of string;

global tbl2: table[string] of string &backend=Broker::MEMORY;

global tbl3: table[string] of string &broker_store="teststore";

event zeek_init()
	{
	terminate();
	}
