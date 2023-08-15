module QUIC;

export {
	const version_strings: table[count] of string = {
		[0x00000001] = "1",
	} &default=function(version: count): string { return fmt("unknown-%x", version); };
}
