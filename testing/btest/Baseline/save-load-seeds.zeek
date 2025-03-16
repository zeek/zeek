# @TEST-DOC: Save seeds and read and assure the UIDs are the same. Regression test for #4209
#
# @TEST-EXEC: zeek --save-seeds myseeds -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: mkdir save && mv *log save
# @TEST-EXEC: zeek-cut -m uid history service < save/conn.log >save/conn.log.cut
#
# @TEST-EXEC: zeek --load-seeds myseeds -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: mkdir load && mv *log load
# @TEST-EXEC: zeek-cut -m uid history service < load/conn.log >load/conn.log.cut
#
# @TEST-EXEC: btest-diff load/conn.log.cut
# @TEST-EXEC: btest-diff save/conn.log.cut
# @TEST-EXEC: diff load/conn.log.cut save/conn.log.cut

@load base/protocols/conn
@load base/protocols/http
