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

	## Whether or not to include vlans in flow tracking.
	##
	## TODO: This should probably be inferred, then also in the canonical
	## ID mapping.
	option include_vlan: bool = F;

	## The directory that the BPF maps are pinned to.
	option pin_path: string = "/sys/fs/bpf/zeek";
}

event zeek_init()
	{
	local opts: XDP::ShuntOptions = [ $attach_mode=attach_mode,
	    $conn_id_map_max_size=conn_id_map_max_size,
	    $ip_pair_map_max_size=ip_pair_map_max_size,
	    $include_vlan=include_vlan, $pin_path=pin_path,  ];

	if ( start_new_xdp )
		start_shunt(opts);
	else
		reconnect(opts);
	}
