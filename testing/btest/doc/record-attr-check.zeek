# @TEST-EXEC: zeek -b %INPUT

type Tag: enum {
    SOMETHING
};

type R: record {
    field1: set[Tag] &default=set();
};
