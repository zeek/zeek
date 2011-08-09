# Makes sure that all policy/* scripts are loaded in test-all-policy.bro; and that
# all scripts loaded there actually exist.

@TEST-EXEC: test -e $DIST/scripts/test-all-policy.bro
@TEST-EXEC: test -d $DIST/scripts
@TEST-EXEC: ( cd $DIST/scripts/policy && find . -name '*.bro' ) | sort >"all scripts found"
@TEST-EXEC: cat $DIST/scripts/test-all-policy.bro | grep '@load' | sed 'sm^\( *# *\)\{0,\}@load *m./mg' | sort >test-all-policy.bro
@TEST-EXEC: diff -u "all scripts found" test-all-policy.bro 1>&2
