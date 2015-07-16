@TEST-EXEC: bro -C -r ${TRACES}/tcp/empty/empty003.trace policy/protocols/tcp/tcp_analysis
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpretransmission.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC: test -f tcpoptions.log
@TEST-EXEC-FAIL: test -f tcpdeadconnection.log
@TEST-EXEC-FAIL: test -f tcprecovery.log
@TEST-EXEC-FAIL: btest-diff tcpretransmission.log
@TEST-EXEC-FAIL: btest-diff tcpreordering.log
@TEST-EXEC: btest-diff tcpoptions.log
@TEST-EXEC-FAIL: btest-diff tcpdeadconnection.log
@TEST-EXEC-FAIL: btest-diff tcprecovery.log

