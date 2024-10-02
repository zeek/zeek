# @TEST-DOC: Breaking and recursive Telemetry::sync() warning
# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr


@load base/frameworks/telemetry

global connections_by_proto_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="connections",
	$unit="",
	$help_text="Total number of monitored connections",
	$label_names=vector("proto")
]);

event zeek_init()
	{
	print "node up";
	Telemetry::counter_family_inc(connections_by_proto_cf, vector("tcp"));
	local ms = Telemetry::collect_metrics("btest");
	}


hook Telemetry::sync()
	{
	# Calling collect_metrics() in Telemetry::sync() is not good as
	# it would invoke Telemetry::sync() recursively. The manager will
	# emit a warning and not run the second Telemetry::sync() invocation.
	local ms = Telemetry::collect_metrics("btest");
	}

hook Telemetry::sync() &priority=-100
	{
	# break is not good as it prevents other Telemetry::sync() hooks
	# from running. This will produce a warning.
	# We could find this via script validation if we wanted to.
	break;
	}
