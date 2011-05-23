# @TEST-EXEC: bro --doc-scripts %INPUT

type Tag: enum {
    SOMETHING
};

type R: record {
    field1: set[Tag] &default=set();
};
