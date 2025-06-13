/*
 * @TEST-DOC: Test that events send via ZeroMQ to other nodes can be handled with JavaScript.
 *
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-REQUIRES: $SCRIPTS/have-zeromq
 *
 * @TEST-PORT: XPUB_PORT
 * @TEST-PORT: XSUB_PORT
 * @TEST-PORT: LOG_PULL_PORT
 *
 * @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
 * @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
 *
 * @TEST-EXEC: zeek --parse-only manager.zeek
 *
 * @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
 * @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../common.zeek %INPUT"
 *
 * @TEST-EXEC: btest-bg-wait 30
 * @TEST-EXEC: btest-diff worker/.stdout
 *
 *
 * @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap.zeek
global ping: event(c: count);

 * @TEST-END-FILE

 * @TEST-START-FILE manager.zeek
@load common.zeek

event tick() {
  Cluster::publish("/test", ping, 42);
  schedule 5msec { tick() };
}

event zeek_init() {
  event tick();
}

event Cluster::node_down(name: string, id: string) {
  print "Cluster::node_down", name;
  terminate();
}

 * @TEST-END-FILE
 */

zeek.on('zeek_init', () => {
  console.log('JS: zeek_init');
  zeek.invoke('Cluster::subscribe', ['/test']);
});

var total = 0;

zeek.on('ping', (c) => {
  ++total;
  console.log('JS: ping', total, c);
  if (total == 5) {
    zeek.invoke('terminate');
  }
});
