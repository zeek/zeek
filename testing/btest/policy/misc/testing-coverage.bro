# Makes sure that all policy scripts are loading in testing.bro; and that all
# scripts loaded there actually exist.

@TEST-EXEC: ( cd $DIST/policy && find . -name '*.bro' ) | sort >"all scripts found"
@TEST-EXEC:  cat $DIST/policy/test-all.bro | grep '@load' | sed 'sm^\( *# *\)\{0,\}@load *m./mg' | sort >test-all.bro
@TEST-EXEC: diff -u "all scripts found" test-all.bro 1>&2
