# @TEST-DOC: Query Broker's telemetry to verify it ends up in Zeek's registry.
# Not compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -r - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC-FAIL: test -f reporter.log

@load base/frameworks/telemetry

redef running_under_test = T;

function print_histogram_metrics(what: string, metrics: vector of Telemetry::HistogramMetric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$prefix, m$opts$name, m$opts$bounds, m$label_names, m?$label_values ? m$label_values : vector();
		# Don't output actual values as they are runtime dependent.
		# print m$values, m$sum, m$observations;
		if ( m$opts?$bounds )
			print m$opts$bounds;
		}
	}

function print_metrics(what: string, metrics: vector of Telemetry::Metric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$prefix, m$opts$name, m$label_names, m?$label_values ? m$label_values : vector(), m$value;

		if (m?$value)
			print "value", m$value;
		}
	}

event zeek_done() &priority=-100
	{
	local broker_metrics = Telemetry::collect_metrics("broker*", "*");
	print_metrics("broker", broker_metrics);
	local broker_histogram_metrics = Telemetry::collect_histogram_metrics("broker*", "*");
	print_histogram_metrics("broker", broker_histogram_metrics);
	}
