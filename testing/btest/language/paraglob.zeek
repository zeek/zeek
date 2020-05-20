# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init ()
{
	local v1 = vector("*", "d?g", "*og", "d?", "d[!wl]g");
	local v2 = vector("once", "!o*", "once");
	local v3 = vector("https://*.google.com/*", "*malware*", "*.gov*");
	local v4 = vector("z*ro", "zero\0zero");

	local p1 = paraglob_init(v1);
	local p2: opaque of paraglob = paraglob_init(v2);
	local p3 = paraglob_init(v3);
	local p4 = paraglob_init(v4);
	local p_eq = paraglob_init(v1);

	# paraglob_init should not modify v1
	print (v1 == vector("*", "d?g", "*og", "d?", "d[!wl]g"));
	# p_eq and p1 should be the same paraglobs
	print paraglob_equals(p_eq, p1);
	print paraglob_equals(p1, p2);

	print paraglob_match(p1, "dog");

	print paraglob_match(p2, "once");
	print paraglob_match(p2, "nothing");
	print paraglob_match(p3, "www.strange-malware-domain.gov");
	print paraglob_match(p4, "zero\0zero");

	# This looks like a lot, but really should complete quickly.
	# Paraglob should stop addition of duplicate patterns.
	local i = 1000000;
	while (i > 0) {
		i = i - 1;
		v3 += v3[1];
	}

	local large_glob: opaque of paraglob = paraglob_init(v3);
	print paraglob_match(large_glob, "www.strange-malware-domain.gov");
}
