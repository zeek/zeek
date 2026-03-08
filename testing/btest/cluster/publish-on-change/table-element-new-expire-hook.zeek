# @TEST-DOC: Test &publish_on_change with TABLE_ELEMENT_NEW and TABLE_ELEMENT_EXPIRE and a short expiration time. The worker does not publish expired elements. This is a sharp tool.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek

# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

redef table_expire_interval = 1msec;
redef table_expire_delay = 1msec;

# Make sure that only the manager sends out expiration events.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
const changes = set(TABLE_ELEMENT_NEW, TABLE_ELEMENT_EXPIRED);
@else
const changes = set(TABLE_ELEMENT_NEW);
@endif

global tbl1: table[string] of string &write_expire=100msec &publish_on_change=[
	$changes=changes,
	$max_batch_size=0,
];
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

function populate_table(round: count)
	{
	local i = 0;
	while ( i < 5 )
		{
		++i;
		local key = fmt("%s-%s-%s", Cluster::node, round, i);
		tbl1[key] = key;
		}
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	populate_table(1);

	# Wait for the expiration to happen, then insert again.
	when ( |tbl1| == 0 )
		{
		populate_table(2);
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node_down", name;
	terminate();
	}

hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	print "ERROR", tcheader;
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common
global total_changes = 0;

event zeek_done()
	{
	print fmt("tbl1: %s", tbl1);
	}

hook Cluster::apply_table_change_infos_policy(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos)
	{
	local id = tcheader$id;
	for ( _, tci in tcinfos )
		{
		++total_changes;
		print "table_change", id, tci;
		}

	# 10 inserts and 10 expirations.
	if ( total_changes == 20 )
		{
		print "saw 20 changes";
		terminate();
		}
	}
# @TEST-END-FILE
