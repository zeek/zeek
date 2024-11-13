# @TEST-DOC: Test cluster backend enum
#
# @TEST-EXEC: zeek -NN Zeek::Cluster_Backend_Broker >>out
# @TEST-EXEC: zeek -b %INPUT >>out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print Cluster::CLUSTER_BACKEND_BROKER, type_name(Cluster::CLUSTER_BACKEND_BROKER);
	}
