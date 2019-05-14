# @TEST-EXEC: zeek -b %INPUT

# To support documentation of type aliases, Bro clones declared types
# (see add_type() in Var.cc) in order to keep track of type names and aliases.
# This test makes sure that the cloning is done in a way that's compatible
# with adding fields to a record type -- we want to be sure that cloning
# a type that contains record types will correctly see field additions to
# those contained-records.

type my_record: record {
    field1: bool;
    field2: string;
};

type super_record: record {
    rec: my_record;
};
type my_table: table[count] of my_record;
type my_vector: vector of my_record;

redef record my_record += {
    field3: count &optional;
};

global a: my_record;
global b: super_record;
global c: my_table;
global d: my_vector;

function test_func()
    {
    a?$field3;
    b$rec?$field3;
    c[0]$field3;
    d[0]$field3;
    }
