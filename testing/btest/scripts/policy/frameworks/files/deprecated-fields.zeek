# @TEST-DOC: Verify the files.log with and without the tx_hosts, rx_hosts and conn_uids fields
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT 2>&1 > out
# @TEST-EXEC: mv files.log files.log.new
# @TEST-EXEC: mv out out.new
# @TEST-EXEC: btest-diff out.new
# @TEST-EXEC: btest-diff files.log.new

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT frameworks/files/deprecated-txhosts-rxhosts-connuids 2>&1 > out
# @TEST-EXEC: mv files.log files.log.deprecated
# @TEST-EXEC: mv out out.deprecated
# @TEST-EXEC: btest-diff out.deprecated
# @TEST-EXEC: btest-diff files.log.deprecated

@load base/frameworks/files
@load base/protocols/http
