module NTP;

export {
	## The descriptions of the NTP mode value, as described
	## in :rfc:`5905`, Figure 1
	const modes: table[count] of string = {
		[1] = "symmetric active",
		[2] = "symmetric passive",
		[3] = "client",
		[4] = "server",
		[5] = "broadcast server",
		[6] = "control",
		[7] = "private",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}
