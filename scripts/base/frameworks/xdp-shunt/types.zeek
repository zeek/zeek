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
}
