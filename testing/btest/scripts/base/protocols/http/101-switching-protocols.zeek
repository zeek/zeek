# This tests that the HTTP analyzer does not generate a dpd error as a
# result of seeing an upgraded connection.
#
# @TEST-EXEC: zeek -r $TRACES/http/websocket.pcap %INPUT
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff .stdout

event http_connection_upgrade(c: connection, protocol: string)
	{
	print fmt("Connection upgraded to %s", protocol);
	}
