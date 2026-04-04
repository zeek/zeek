# @TEST-DOC: Ensures that large sets of data work with paraglob.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

event zeek_init()
	{
	const pattern_vec = vector("amber=*", "bridge=*", "cushion=*", "dazzle=*", "effort=*",
		"falcon=*", "glimpse=*", "harvest=*", "ignite=*", "jovial=*", "kitchen=*",
		"lantern=*", "mosaic=*", "nurture=*", "octopus=*", "prism=*", "quarrel=*",
		"ribbon=*", "shadow=*", "timber=*", "uplift=*", "violet=*", "whisper=*",
		"zenith=*", "anchor=*", "breeze=*", "copper=*", "dolphin=*", "ember=*",
		"forest=*", "garden=*", "harbor=*", "island=*", "jungle=*", "kindle=*",
		"meadow=*", "nebula=*", "origin=*", "puzzle=*", "quartz=*", "rustic=*",
		"spiral=*", "temple=*", "unique=*", "voyage=*", "wonder=*", "yellow=*",
		"archive=*", "blossom=*", "crystal=*"
	);

	const pattern_glob = paraglob_init(pattern_vec);

	print paraglob_match(pattern_glob, "amber=");
	print paraglob_match(pattern_glob, "voyage=");
	}
