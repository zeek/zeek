##! Reconnect to the XDP program at init when this script is loaded.

module XDP;

export {
	## Whether we want to start a new XDP program or reconnect to an existing
	## one.
	option start_new_xdp: bool = F;

	## The XDP mode to attach via.
	option attach_mode: AttachMode = UNSPEC;

	## The max size of the conn_id map. Must match what the BPF program was
	## loaded with, or it will fail to load.
	option conn_id_map_max_size: count = 65535;

	## The max size of the IP pair map. Must match what the BPF program was
	## loaded with, or it will fail to load.
	option ip_pair_map_max_size: count = 65535;

	## The directory that the BPF maps are pinned to.
	option pin_path: string = "/sys/fs/bpf/zeek";

	## If we should force not using VLANs, regardless of conn_id_ctx. This
	## is used to override the VLAN handling from loading the vlan conn key
	## factory if necessary.
	option force_no_vlans: bool = F;

	## If we should load the XDP pins. By default, only load if it's in a
	## cluster worker or not in a cluster.
	option should_load: bool = Cluster::local_node_type() == Cluster::WORKER
	    || Cluster::local_node_type() == Cluster::NONE;
}

function should_load_with_vlan(): bool
	{
	local fields = record_fields(conn_id_ctx);
	return "vlan" in fields && "inner_vlan" in fields;
	}

event zeek_init()
	{
	if ( ! should_load )
		return;

	vlans_included = ( ! force_no_vlans ) && should_load_with_vlan();

	local opts: XDP::ShuntOptions = [ $attach_mode=attach_mode,
	    $conn_id_map_max_size=conn_id_map_max_size,
	    $ip_pair_map_max_size=ip_pair_map_max_size,
	    $include_vlan=vlans_included, $pin_path=pin_path,  ];

	if ( start_new_xdp )
		start_shunt(opts);
	else
		reconnect(opts);
	}
