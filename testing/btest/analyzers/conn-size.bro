# @TEST-EXEC: bro -C -r ${TRACES}/conn-size.trace tcp udp icmp report_conn_size_analyzer=T use_connection_compressor=F
# @TEST-EXEC: btest-diff conn.log
