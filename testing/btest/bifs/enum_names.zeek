# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type Color: enum { RED, GREEN, BLUE };
type ColorAlias: Color;

redef enum Color += { PURPLE };

module Monochrome;

type Color: enum { WHITE, BLACK };


print "with types";
print enum_names(Color);
print enum_names(ColorAlias);
print enum_names(Monochrome::Color);

print "with strings";
print enum_names("Color");
print enum_names("ColorAlias");
print enum_names("Monochrome::Color");
