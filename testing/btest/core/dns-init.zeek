# We once had a bug where DNS lookups at init time lead to an immediate crash. 
#
# @TEST-EXEC: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

const foo: set[addr] = {
     google.com
};

