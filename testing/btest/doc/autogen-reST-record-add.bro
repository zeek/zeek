# @TEST-EXEC: bro --doc-scripts %INPUT

# When in doc mode, bro will clone declared types (see add_type() in Var.cc)
# in order to keep track of the identifier name associated with the new type.
# This test makes sure that the cloning is done in a way that's compatible
# with adding fields to a record type -- we want to be sure that cloning
# a record that contains other record fields will correctly see field
# additions to those contained-records.

type my_record: record {
    field1: bool;
    field2: string;
};

type super_record: record {
    rec: my_record;
};

redef record my_record += {
    field3: count &optional;
};

global a: my_record;

global b: super_record;

function test_func()
{
    a?$field3;
    b$rec?$field3;
}
