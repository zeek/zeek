# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek -b -X zeexygen.config %INPUT Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-diff test.rst

@TEST-START-FILE zeexygen.config
script_summary	zeexygen/example.zeek	test.rst
@TEST-END-FILE

@load zeexygen
