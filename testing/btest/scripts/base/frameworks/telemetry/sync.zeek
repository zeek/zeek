# @TEST-DOC: Verify Telemetry::sync() is invoked for metric scraping via the Prometheus HTTP endpoint.
# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-REQUIRES: which jq
# @TEST-REQUIRES: which curl
#
# @TEST-PORT: METRICS_PORT
#
# @TEST-EXEC: chmod +x fetch-metrics.sh
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run zeek ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/up 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: ./fetch-metrics.sh 1.trace metrics1.txt
# @TEST-EXEC: ./fetch-metrics.sh 2.trace metrics2.txt
# @TEST-EXEC: ./fetch-metrics.sh 3.trace metrics3.txt
# @TEST-EXEC: btest-bg-wait 10
#
# @TEST-EXEC: btest-diff zeek/.stdout
# @TEST-EXEC: btest-diff metrics1.txt
# @TEST-EXEC: btest-diff metrics2.txt
# @TEST-EXEC: btest-diff metrics3.txt

@TEST-START-FILE fetch-metrics.sh
#! /usr/bin/env bash
set -ux
trace_file=$1
output_file=$2

PORT=$(echo ${METRICS_PORT} | cut -d '/' -f 1)
URL=http://localhost:${PORT}/metrics

curl -m 5 --trace $trace_file $URL | grep ^btest > $output_file

exit 0
@TEST-END-FILE

@load base/frameworks/telemetry

redef exit_only_after_terminate = T;
redef Telemetry::metrics_port = to_port(getenv("METRICS_PORT"));

event zeek_init()
	{
	print "node up";
	system("touch up");
	}

global connections_by_proto_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="connections",
	$unit="",
	$help_text="Total number of monitored connections",
	$label_names=vector("proto")
]);

global sync_calls = 0;

hook Telemetry::sync()
	{
	++sync_calls;
	local proto = sync_calls == 1 ? "tcp" : "udp";
	print "sync", sync_calls, proto;
	Telemetry::counter_family_inc(connections_by_proto_cf, vector(proto));

	if ( sync_calls == 3 )
		terminate();
	}
