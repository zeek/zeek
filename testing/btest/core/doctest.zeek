# @TEST-REQUIRES: zeek --test -h >/dev/null
# @TEST-EXEC: ZEEK_SEED_FILE= zeek --test >&2
#
# @TEST-DOC: Run the doctest-based unit tests.
#
# Note that we need to clear the hash seed as the units tests seem to make
# some assumptions about ordering that the custom seed breaks.
