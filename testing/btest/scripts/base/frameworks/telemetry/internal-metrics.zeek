# @TEST-DOC: Query some internal broker/caf related metrics as they use the int64_t versions, too.
# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC-FAIL: test -f reporter.log

@load base/frameworks/telemetry

function print_histogram_metrics(what: string, metrics: vector of Telemetry::HistogramMetric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$name, m$opts$bounds, m$opts$labels, m$labels;
		# Don't output actual values as they are runtime dependent.
		# print m$values, m$sum, m$observations;
		if ( m$opts?$count_bounds )
			print m$opts$count_bounds;
		}
	}

function print_metrics(what: string, metrics: vector of Telemetry::Metric)
	{
	print fmt("### %s |%s|", what, |metrics|);
	for (i in metrics)
		{
		local m = metrics[i];
		print m$opts$metric_type, m$opts$name, m$opts$labels, m$labels, m$value;

		if (m?$count_value)
			print "count_value", m$count_value;
		}
	}

event zeek_done() &priority=-100
	{
	local broker_metrics = Telemetry::collect_metrics("broker", "*");
	print_metrics("broker", broker_metrics);
	local caf_metrics = Telemetry::collect_metrics("caf*", "*");
	print_metrics("caf", caf_metrics);
	local caf_histogram_metrics = Telemetry::collect_histogram_metrics("caf*", "*");
	print_histogram_metrics("caf", caf_histogram_metrics);
	}
