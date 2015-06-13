@TEST-EXEC: bro -C -r ${TRACES}/tcp/heuristics/rto-approximation.trace policy/protocols/tcp/tcp_analysis
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC: btest-diff tcpdeadconnection.log
@TEST-EXEC: btest-diff tcprecovery.log
@TEST-EXEC: btest-diff tcpretransmissions.log
@TEST-EXEC: btest-diff tcpoptions.log

