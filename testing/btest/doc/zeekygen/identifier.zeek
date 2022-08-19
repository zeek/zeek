# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b -X zeekygen.config %INPUT Broker::default_port=$BROKER_PORT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff test.rst

@TEST-START-FILE zeekygen.config
identifier	ZeekygenExample::*	test.rst
@TEST-END-FILE

@load zeekygen
