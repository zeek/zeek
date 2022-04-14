# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing LoadFileExtended
# @TEST-EXEC: cp -r %DIR/plugin-load-file-extended/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -r $TRACES/wikipedia.trace -b Testing::LoadFileExtended xxx xxx2 yyy -s abc.sig >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE xxx.zeek

event zeek_init() {
    print "original script";
}

# @TEST-END-FILE

# @TEST-START-FILE xxx2.zeek
# Test loading from script land.
@load xxx3
@load-sigs def.sig
# @TEST-END-FILE

# @TEST-START-FILE xxx3.zeek
# empty
# @TEST-END-FILE

# @TEST-START-FILE abc.sig
# empty
# @TEST-END-FILE

# @TEST-START-FILE def.sig
# empty
# @TEST-END-FILE
