# Makes sure that all base/* scripts are loaded by default via
# init-default.zeek; and that all scripts loaded there actually exist.
#
# This test will fail if a new zeek script is added under the scripts/base/
# directory and it is not also added as an @load in base/init-default.zeek.
# In some cases, a script in base is loaded based on the zeek configuration
# (e.g. cluster operation), and in such cases, the missing_loads baseline
# can be adjusted to tolerate that.

#@TEST-EXEC: test -d $DIST/scripts/base
#@TEST-EXEC: test -e $DIST/scripts/base/init-default.zeek
#@TEST-EXEC: ( cd $DIST/scripts/base && find . -name '*.zeek' ) | sort >"all scripts found"
#@TEST-EXEC: zeek misc/loaded-scripts
#@TEST-EXEC: (test -L $BUILD && basename $(readlink $BUILD) || basename $BUILD) >buildprefix
#@TEST-EXEC: cat loaded_scripts.log | egrep -v "/build/scripts/|$(cat buildprefix)/scripts/|/loaded-scripts.zeek|#" | sed 's#/./#/#g'  >loaded_scripts.log.tmp
#@TEST-EXEC: cat loaded_scripts.log.tmp | sed 's/ //g' | sed -e ':a' -e '$!N' -e 's/^\(.*\).*\n\1.*/\1/' -e 'ta' >prefix
#@TEST-EXEC: cat loaded_scripts.log.tmp | sed 's/ //g' | sed "s#`cat prefix`#./#g" | sort >init-default.zeek
#@TEST-EXEC: diff -u "all scripts found" init-default.zeek | egrep "^-[^-]" > missing_loads
#@TEST-EXEC: btest-diff missing_loads
