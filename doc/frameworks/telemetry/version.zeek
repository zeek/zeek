global version_gf = Telemetry::register_gauge_family([
	$prefix="zeek",
	$name="version_info",
	$unit="1",
	$help_text="The Zeek version",
	$label_names=vector("version_number", "major", "minor", "patch", "commit", "beta", "debug","version_string")
]);

event zeek_init()
	{
	local v = Version::info;
	local labels = vector(cat(v$version_number),
	                      cat(v$major), cat(v$minor), cat (v$patch),
	                      cat(v$commit),
	                      v$beta ? "true" : "false",
	                      v$debug ? "true" : "false",
	                      v$version_string);
	Telemetry::gauge_family_set(version_gf, labels, 1.0);
	}
