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
    };

    type ShuntedStats: record {
        packets_from_orig: count;
        bytes_from_orig: count;
        packets_from_resp: count;
        bytes_from_resp: count;
        timestamp: time &optional; # The last shunted timestamp seen, if any

        present: bool; # If this means anything :) probably a better way
    };
}
