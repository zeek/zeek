# This check piggy-backs on the test-all-policy.zeek test, assuming that every
# loadable script is referenced there.  The only additional check here is
# that the zeekygen package should even load scripts that are commented
# out in test-all-policy.zeek because the zeekygen package is only loaded
# when generated documentation and will terminate has soon as zeek_init
# is handled, even if a script will e.g. put Zeek into listen mode or otherwise
# cause it to not terminate after scripts are parsed.

# @TEST-EXEC: bash %INPUT $DIST/scripts/test-all-policy.zeek $DIST/scripts/zeekygen/__load__.zeek

error_count=0

error_msg() {
    error_count=$((error_count + 1))
    echo "$@" 1>&2
}

if [ $# -ne 2 ]; then
    print "incorrect arguments"
    exit 1
fi

all_loads=$(grep -E "#[[:space:]]*@load.*" $1 | sed 's/#[[:space:]]*@load[[:space:]]*//g')
zeekygen_loads=$(grep -E "@load.*" $2 | sed 's/@load[[:space:]]*//g')

for f in $all_loads; do
    echo "$zeekygen_loads" | grep -q $f || error_msg "$f not loaded in zeekygen/__load__.zeek"
done

if [ $error_count -gt 0 ]; then
    exit 1
fi

exit 0
