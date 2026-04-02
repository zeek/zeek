##! Loads or reuses an XDP program. By default, loading
##! this means that an XDP program is already started, and two BPF
##! maps are found corresponding to the two ways to shunt traffic.
##!
##! You may also start the XDP program within this Zeek instance
##! by redefining :zeek:see:`XDP::start_new_xdp`.
@ifdef ( XDP::__load_and_attach )
module XDP;

@load ./main

export {
	## Set this to true in order to tell Zeek to load the shunting
	## XDP program itself. This is generally only useful for
	## standalone instances, testing, or some unique deployment
	## scenarios.
	const start_new_xdp: bool = F &redef;

	## The XDP mode to attach via.
	const attach_mode: AttachMode = UNSPEC &redef;

	## The max size of the conn_id map. Only necessary if starting
	## a new XDP program.
	const conn_id_map_max_size: count = 65535 &redef;

	## The max size of the IP pair map. Only necessary if starting
	## a new XDP program.
	const ip_pair_map_max_size: count = 65535 &redef;

	## The directory that the BPF maps are pinned to.
	const pin_path: string = "/sys/fs/bpf/zeek" &redef;

	## If we should force not using VLANs, regardless of conn_id_ctx. This
	## is used to override the VLAN handling from loading the vlan conn key
	## factory if necessary.
	const force_no_vlans: bool = F &redef;

	## If we should load the XDP pins. By default, only load if it's in a
	## cluster worker or not in a cluster. This is helpful for any
	## nodes that don't read traffic, so they don't try to connect to
	## a possibly nonexistent map.
	const should_load: bool = Cluster::local_node_type() == Cluster::WORKER
	    || Cluster::local_node_type() == Cluster::NONE &redef;
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
		load_and_attach(opts);
	else
		reuse_maps(opts);
	}

@endif
