# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek -b -X zeexygen.config %INPUT
# @TEST-EXEC: btest-diff autogen-reST-type-aliases.rst

@TEST-START-FILE zeexygen.config
identifier	ZeexygenTest::*	autogen-reST-type-aliases.rst
@TEST-END-FILE

module ZeexygenTest;

export {
	## This is just an alias for a builtin type ``bool``.
	type TypeAlias: bool;

	## This type should get its own comments, not associated w/ TypeAlias.
	type NotTypeAlias: bool;

	## This cross references ``bool`` in the description of its type
	## instead of ``TypeAlias`` just because it seems more useful --
	## one doesn't have to click through the full type alias chain to
	## find out what the actual type is...
	type OtherTypeAlias: TypeAlias;

	## But this should reference a type of ``TypeAlias``.
	global a: TypeAlias;

	## And this should reference a type of ``OtherTypeAlias``.
	global b: OtherTypeAlias;

	type MyRecord: record {
		f1: TypeAlias;
		f2: OtherTypeAlias;
		f3: bool;
	};
}
