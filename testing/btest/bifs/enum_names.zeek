# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type Color: enum { RED, GREEN, BLUE };
type ColorAlias: Color;

redef enum Color += { PURPLE };

print enum_names(Color);
print enum_names(ColorAlias);
