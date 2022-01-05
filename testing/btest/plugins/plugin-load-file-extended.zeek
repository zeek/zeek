# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing LoadFileExtended
# @TEST-EXEC: cp -r %DIR/plugin-load-file-extended/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -r $TRACES/wikipedia.trace -b Testing::LoadFileExtended xxx yyy -s abc.sig >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE xxx.zeek

event zeek_init() {
    print "original script";
}

# @TEST-END-FILE

# @TEST-START-FILE abc.sig
# empty
# @TEST-END-FILE
