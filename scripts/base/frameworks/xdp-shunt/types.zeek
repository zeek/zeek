module XDP;

export {
    type AttachMode: enum {
        UNSPEC = 0,
        NATIVE = 1,
        SKB = 2,
        HW = 3,
    };

    type ShuntOptions: record {
        attach_mode: AttachMode &default=UNSPEC;
        conn_id_map_max_size: count &default=65535; # Must be >1
        ip_pair_map_max_size: count &default=65535; # Must be >1
        include_vlan: bool &default=F; # Whether we include vlans in the keys
        pin_path: string &default="/sys/fs/bpf/zeek"; # Directory to pin the BPF maps into
    };

    type ShuntedStats: record {
        packets_from_1: count; # From IP1, or orig in conn_id
        bytes_from_1: count; # From IP1, or orig in conn_id
        packets_from_2: count; # From IP2, or resp in conn_id
        bytes_from_2: count; # From IP2, or resp in conn_id
        timestamp: time &optional; # The last shunted timestamp seen, if any

        present: bool; # If this means anything :) probably a better way
    };

    # Essentially a sorted conn_id
    type canonical_id: record {
        ip1: addr &log;
        ip1_port: port &log;
        ip2: addr &log;
        ip2_port: port &log;
        proto: count &log;

        outer_vlan_id: count &optional &log; # The outer vlan, if any. Bidirectional
        inner_vlan_id: count &optional &log; # The inner vlan, if any. Bidirectional
    };

    type shunt_table: table[canonical_id] of ShuntedStats;

    type ip_pair: record {
        ip1: addr;
        ip2: addr;

        outer_vlan_id: count &optional; # The outer vlan, if any. Bidirectional
        inner_vlan_id: count &optional; # The inner vlan, if any. Bidirectional
    };

    type ip_pair_shunt_table: table[ip_pair] of ShuntedStats;
}
