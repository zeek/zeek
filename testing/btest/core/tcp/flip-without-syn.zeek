# @TEST-EXEC: zeek -r $TRACES/tcp/http-on-irc-port-missing-syn.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

# @TEST-DOC: Regression test for #2191: missing SYN and misleading well-known port. Zeek flips, and DPD still figures out the protocol ok.
