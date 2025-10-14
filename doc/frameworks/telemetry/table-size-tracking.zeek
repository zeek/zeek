module Tunnel;

global tunnels_active_size_gf = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="monitored_tunnels_active",
	$unit="1",
	$help_text="Number of currently active tunnels as tracked in Tunnel::active"
]);

global tunnels_active_size_gauge = Telemetry::gauge_with(tunnels_active_size_gf);

global tunnels_active_footprint_gf = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="monitored_tunnels_active_footprint",
	$unit="1",
	$help_text="Footprint of the Tunnel::active table"
]);

global tunnels_active_footprint_gauge = Telemetry::gauge_with(tunnels_active_footprint_gf);

hook Telemetry::sync() {

	Telemetry::gauge_set(tunnels_active_size_gauge, |Tunnel::active|);
	Telemetry::gauge_set(tunnels_active_footprint_gauge, val_footprint(Tunnel::active));
}
