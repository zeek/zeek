@TEST-EXEC: bro -C -r ${TRACES}/tcp/rto/rto007.trace policy/protocols/tcp/tcp_analysis
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC: btest-diff tcpretransmissions.log
@TEST-EXEC: btest-diff tcpoptions.log
@TEST-EXEC: btest-diff tcpdeadconnection.log
@TEST-EXEC: btest-diff tcprecovery.log

