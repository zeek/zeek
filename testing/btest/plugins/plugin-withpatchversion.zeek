# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Testing WithPatchVersion
# @TEST-EXEC: cp -r %DIR/plugin-withpatchversion-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=$(pwd) zeek -N Testing::WithPatchVersion >> output
# @TEST-EXEC: btest-diff output
