# @TEST-DOC: Checks dot directories are not searched for `ZEEK_PLUGIN_PATH`.

# @TEST-EXEC: mkdir 1
# @TEST-EXEC: cd 1 && ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing Plugin1 >/dev/null 2>&1
# @TEST-EXEC: cd 1 && (./configure --zeek-dist=${DIST} && make) >/dev/null 2>&1

# It is fine to move the compiled pluging around and we can still load it.
# @TEST-EXEC: mv 1 11
# @TEST-EXEC: ZEEK_PLUGIN_PATH=. zeek -b -N Testing::Plugin1 # Baseline

# If the plugin is in a dot directory unser `ZEEK_PLUGIN_PATH`
# it is not loaded anymore.
# @TEST-EXEC: mv 11 .1
# @TEST-EXEC-FAIL: ZEEK_PLUGIN_PATH=. zeek -b -N Testing::Plugin1 # Plugin in dot.

# If however `ZEEK_PLUGIN_PATH` itself is the only dot directory
# in the path the plugin gets loaded.
# @TEST-EXEC: mkdir .plug
# @TEST-EXEC: mv .1 .plug/1
# @TEST-EXEC: ZEEK_PLUGIN_PATH=.plug zeek -b -N Testing::Plugin1 # ZEEK_PLUGIN_PATH is dot.
