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
        conn_id_map_max_size: count &default=65536; # Must be >1
        ip_pair_map_max_size: count &default=65536; # Must be >1
    };

    type ShuntedStats: record {
        packets_from_orig: count;
        bytes_from_orig: count;
        packets_from_resp: count;
        bytes_from_resp: count;
        fin: count; # The number of TCP fin packets shunted
        rst: count; # The number of TCP rst packets shunted
        timestamp: time &optional; # The last shunted timestamp seen, if any

        present: bool; # If this means anything :) probably a better way
    };

    type shunt_table: table[conn_id] of ShuntedStats;

    type ip_pair: record {
        ip1: addr;
        ip2: addr;
    };
    type ip_pair_shunt_table: table[ip_pair] of ShuntedStats;
}
