@TEST-EXEC: bro -C -r ${TRACES}/tcp/rto/rto003.trace policy/protocols/tcp/tcp_analysis
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC-FAIL: test -f tcprecovery.log
@TEST-EXEC: btest-diff tcpretransmissions.log
@TEST-EXEC: btest-diff tcpoptions.log
@TEST-EXEC: btest-diff tcpdeadconnection.log

