# We once had a bug where DNS lookups at init time lead to an immediate crash.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr
# @TEST-EXEC: btest-diff .stdout

const foo: set[addr] = {
     blocking_lookup_hostname("google.com")
};

print foo;
