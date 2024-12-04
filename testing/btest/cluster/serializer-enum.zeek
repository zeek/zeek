# @TEST-DOC: Test cluster backend enum
#
# @TEST-EXEC: zeek -NN Zeek::Broker_Serializer >>out
# @TEST-EXEC: zeek -NN Zeek::Binary_Serializer >>out
# @TEST-EXEC: zeek -b %INPUT >>out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print Cluster::EVENT_SERIALIZER_BROKER_BIN_V1, type_name(Cluster::EVENT_SERIALIZER_BROKER_BIN_V1);
	print Cluster::EVENT_SERIALIZER_BROKER_JSON_V1, type_name(Cluster::EVENT_SERIALIZER_BROKER_JSON_V1);
	print Cluster::LOG_SERIALIZER_ZEEK_BIN_V1, type_name(Cluster::LOG_SERIALIZER_ZEEK_BIN_V1);
	}
