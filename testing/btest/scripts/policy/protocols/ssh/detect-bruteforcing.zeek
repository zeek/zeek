# @TEST-EXEC: zeek -C -r $TRACES/ssh/sshguess.pcap %INPUT
# @TEST-EXEC: btest-diff notice.log

@load protocols/ssh/detect-bruteforcing
redef SSH::password_guesses_limit=10;
