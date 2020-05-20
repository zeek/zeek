# Makes sure that all policy/* scripts are loaded in
# scripts/test-all-policy.zeek and that all scripts loaded there actually exist.
#
# This test will fail if new zeek scripts are added to the scripts/policy/
# directory.  Correcting that just involves updating
# scripts/test-all-policy.zeek to @load the new zeek scripts.

@TEST-EXEC: test -e $DIST/scripts/test-all-policy.zeek
@TEST-EXEC: test -d $DIST/scripts
@TEST-EXEC: ( cd $DIST/scripts/policy && find . -name '*.zeek' ) | sort >"all scripts found"
@TEST-EXEC: cat $DIST/scripts/test-all-policy.zeek | grep '@load' | sed 'sm^\( *# *\)\{0,\}@load *m./mg' | sort >test-all-policy.zeek
@TEST-EXEC: diff -u "all scripts found" test-all-policy.zeek 1>&2
