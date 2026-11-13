# @TEST-DOC: -O cache-ZAM stores compiled bodies on a first run and reuses them on a second, with identical results.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# A cold run populates the cache, a warm run loads from it.
# @TEST-EXEC: ZEEK_ZAM_CACHE_DIR=cache ZEEK_ZAM_CACHE_DEBUG=1 zeek -b -O cache-ZAM %INPUT >cold 2>cold-debug
# @TEST-EXEC: test -n "$(ls cache)"
# @TEST-EXEC: grep -q '^ZAM-cache-outcome stored' cold-debug
# @TEST-EXEC: ! grep -q '^ZAM-cache-outcome hit' cold-debug
# @TEST-EXEC: ZEEK_ZAM_CACHE_DIR=cache ZEEK_ZAM_CACHE_DEBUG=1 zeek -b -O cache-ZAM %INPUT >warm 2>warm-debug
# @TEST-EXEC: grep -q '^ZAM-cache-outcome hit' warm-debug
# @TEST-EXEC: btest-diff cold
# @TEST-EXEC: cmp cold warm
#
# ZEEK_ZAM_CACHE enables the cache like the option does.
# @TEST-EXEC: ZEEK_ZAM_CACHE=1 ZEEK_ZAM_CACHE_DIR=cache ZEEK_ZAM_CACHE_DEBUG=1 zeek -b %INPUT >env 2>env-debug
# @TEST-EXEC: grep -q '^ZAM-cache-outcome hit' env-debug
# @TEST-EXEC: cmp cold env
#
# Without the option, naming a cache directory doesn't enable caching.
# @TEST-EXEC: mkdir unused
# @TEST-EXEC: ZEEK_ZAM_CACHE_DIR=unused zeek -b -O ZAM %INPUT >plain
# @TEST-EXEC: test -z "$(ls unused)"
# @TEST-EXEC: cmp cold plain
#
# An unusable cache directory warns and falls back to normal compilation.
# @TEST-EXEC: touch not-a-dir
# @TEST-EXEC: ZEEK_ZAM_CACHE_DIR=not-a-dir zeek -b -O cache-ZAM %INPUT >bad 2>bad-stderr
# @TEST-EXEC: grep -q 'warning: ZAM body cache disabled: can.t use not-a-dir as cache directory' bad-stderr
# @TEST-EXEC: cmp cold bad

type R: record {
	a: count;
	b: string &default="dflt";
};

function classify(n: count): string
	{
	switch ( n % 3 )
		{
		case 0:
			return "fizz";
		case 1:
			return "buzz";
		default:
			return "other";
		}
	}

function total(t: table[string] of count): count
	{
	local sum = 0;
	for ( _, v in t )
		sum += v;
	return sum;
	}

event zeek_init()
	{
	local t: table[string] of count = { ["x"] = 1, ["y"] = 2, ["z"] = 3 };
	print total(t);

	for ( i in vector(1, 2, 3, 4) )
		print i, classify(i);

	local r = R($a=5);
	print r, cat("a=", r$a, ", b=", r$b);
	}
