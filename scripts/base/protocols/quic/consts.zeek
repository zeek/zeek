module QUIC;

export {
	const version_strings: table[count] of string = {
		[0x00000001] = "1",
		[0x6b3343cf] = "quicv2",
		[0xff000016] = "draft-22",
		[0xff000017] = "draft-23",
		[0xff000018] = "draft-24",
		[0xff000019] = "draft-25",
		[0xff00001a] = "draft-26",
		[0xff00001b] = "draft-27",
		[0xff00001c] = "draft-28",
		[0xff00001d] = "draft-29",
		[0xff00001e] = "draft-30",
		[0xff00001f] = "draft-30",
		[0xff000020] = "draft-32",
		[0xff000021] = "draft-33",
		[0xff000022] = "draft-34",
		[0xfaceb001] = "mvfst (faceb001)",
		[0xfaceb002] = "mvfst (faceb002)",
		[0xfaceb00e] = "mvfst (faceb00e)",
		[0xfaceb011] = "mvfst (faceb011)",
		[0xfaceb012] = "mvfst (faceb012)",
		[0xfaceb013] = "mvfst (faceb013)",
	} &default=function(version: count): string { return fmt("unknown-%x", version); };
}
