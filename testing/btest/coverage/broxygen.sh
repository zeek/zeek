# This check piggy-backs on the test-all-policy.bro test, assuming that every
# loadable script is referenced there.  The only additional check here is
# that the broxygen package should even load scripts that are commented
# out in test-all-policy.bro because the broxygen package is only loaded
# when generated documentation and will terminate has soon as bro_init
# is handled, even if a script will e.g. put Bro into listen mode or otherwise
# cause it to not terminate after scripts are parsed.

# @TEST-EXEC: bash %INPUT $DIST/scripts/test-all-policy.bro $DIST/scripts/broxygen/__load__.bro

error_count=0

error_msg()
    {
    error_count=$((error_count+1))
    echo "$@" 1>&2;
    }

if [ $# -ne 2 ]; then
    print "incorrect arguments"
    exit 1
fi

all_loads=$(egrep "#[[:space:]]*@load.*" $1 | sed 's/#[[:space:]]*@load[[:space:]]*//g')
broxygen_loads=$(egrep "@load.*" $2 | sed 's/@load[[:space:]]*//g')

for f in $all_loads; do
    echo "$broxygen_loads" | grep -q $f || error_msg "$f not loaded in broxygen/__load__.bro"
done

if [ $error_count -gt 0 ]; then
    exit 1;
fi

exit 0
