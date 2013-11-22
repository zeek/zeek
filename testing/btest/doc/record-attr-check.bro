# @TEST-EXEC: bro -b %INPUT

type Tag: enum {
    SOMETHING
};

type R: record {
    field1: set[Tag] &default=set();
};
