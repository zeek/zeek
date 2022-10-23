# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

# Note that while modifying container membership during for-loop iteration is
# supposed to be undefined-behavior, it should be practically ok to have this
# test perform such operations if they always `break` out of the loop
# immediately afterward.

local t = table([1] = "one", [2] = "two", [3] = "three");

for ( i in t )
	# Modifying an existing element is not qualified as modifying membership,
	# so this doesn't trigger a warning.
	t[i] = cat(i);

print t;

for ( i in t )
	{
	# Adding an element in a loop should trigger a warning.
	t[4] = "four";
	break;
	}

print t;

for ( i in t )
	{
	# Deleting an element in a loop should trigger a warning.
	delete t[4];
	break;
	}

print t;

for ( i in t )
	# Trying to delete a nonexistent element within in a loop does not
	# actually modify membership, so does not trigger a warning.
	delete t[0];

print t;

local s = set(1, 2, 3);

for ( n in s )
	# Trying to add an existing element within in a loop does not
	# actually modify membership, so does not trigger a warning.
	add s[1];

for ( n in s )
	{
	# Adding an element in a loop should trigger a warning.
	add s[4];
	break;
	}

print s;

for ( n in s )
	{
	# Deleting an element in a loop should trigger a warning.
	delete s[4];
	break;
	}

print s;

for ( n in s )
	# Trying to delete a nonexistent element within in a loop does not
	# actually modify membership, so does not trigger a warning.
	delete s[0];

print s;
