# @TEST-DOC: Startup a manager running the ZeroMQ proxy thread and have a worker connect. The manager queries its own metrics once the worker is there to list the ZeroMQ proxy telemetry.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: have-javascript
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: MANAGER_METRICS_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE query-prometheus.js
// Use JavaScript for more pleasure comapred to curl or Zeek's ActiveHTTP.
const http = require('http');

zeek.on('Cluster::node_up', (name, id) => {
  let p = parseInt(process.env.MANAGER_METRICS_PORT);
  let url = `http://127.0.0.1:${p}/metrics`;

  http.get(url, {timeout: 5000}, (res) => {
    let rawData = '';
    if ( res.statusCode != 200 )
      throw res.statusCode;

    res.on('data', (chunk) => { rawData += chunk; });
    res.on('end', () => {
      rawData
        .split(/\n+/)
        .filter(line => line.startsWith('zeek_cluster_zeromq_proxy'))
        .sort()
        .forEach(line => {
          let [name, val] = line.split(/ /);
          console.log(name, '> 0', parseInt(val, 10) > 0);
        });

      // Publish finish() event to the worker once we've munged all metrics.
      zeek.invoke('publish_finish');
   });
  });
});
# @TEST-END-FILE query-prometheus.js

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global finish: event(name: string);
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
@load ./query-prometheus.js

# Trampoline for JavaScript to publish.
function publish_finish()
	{
	Cluster::publish(Cluster::worker_topic, finish, Cluster::node);
	}

# Enable the Prometheus HTTP listener on http://localhost:<MANAGER_METRICS_PORT>/metrics
redef Telemetry::metrics_port = to_port(getenv("MANAGER_METRICS_PORT"));

# If the worker vanishes, shutdown the manager.
event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	terminate();
}
# @TEST-END-FILE
