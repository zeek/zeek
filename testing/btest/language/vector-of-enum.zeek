# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# Type inference for vector constructor comprised of enums should work fine
# (previously the internal merge_types code did not handle enums).

type color: enum { Red, Green, Blue };
global v = vector(Red, Green, Blue);
print type_name(v), v;
