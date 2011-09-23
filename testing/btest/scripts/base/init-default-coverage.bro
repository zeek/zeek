# Makes sure that all base/* scripts are loaded by default via init-default.bro;
# and that all scripts loaded there in there actually exist.

#@TEST-EXEC: test -d $DIST/scripts/base
#@TEST-EXEC: test -e $DIST/scripts/base/init-default.bro
#@TEST-EXEC: ( cd $DIST/scripts/base && find . -name '*.bro' ) | sort >"all scripts found"
#@TEST-EXEC: bro misc/loaded-scripts
#@TEST-EXEC: cat loaded_scripts.log | egrep -v '/build/|/loaded-scripts.bro|#' | awk 'NR>1{print $2}' | sed 's#/./#/#g'  >loaded_scripts.log.tmp
#@TEST-EXEC: cat loaded_scripts.log.tmp | sed -e ':a' -e '$!N' -e 's/^\(.*\).*\n\1.*/\1/' -e 'ta' >prefix
#@TEST-EXEC: cat loaded_scripts.log.tmp | sed "s#`cat prefix`#./#g" | sort >init-default.bro
#@TEST-EXEC: diff -u "all scripts found" init-default.bro 1>&2
