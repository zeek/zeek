# @TEST-EXEC: bro --doc-scripts %INPUT
# @TEST-EXEC: btest-diff autogen-reST-type-aliases.rst

## This is just an alias for a builtin type ``bool``.
type TypeAlias: bool;

## We decided that creating alias "chains" might not be so useful to document
## so this type just creates a cross reference to ``bool``.
type OtherTypeAlias: TypeAlias;

## But this should reference a type of ``TypeAlias``.
global a: TypeAlias;

## And this should reference a type of ``OtherTypeAlias``.
global b: OtherTypeAlias;
