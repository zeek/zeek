# @TEST-DOC: Verify that removing or re-adding the curve25519-sha256 entry controls whether its key exchange is parsed.
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_curve25519.pcap %INPUT
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: mv ssh.log ssh-default.log && mv conn.log conn-default.log
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_curve25519.pcap %INPUT remove.zeek
# @TEST-EXEC: test -f weird.log
# @TEST-EXEC: mv ssh.log ssh-removed.log && mv conn.log conn-removed.log && mv weird.log weird-removed.log
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_curve25519.pcap %INPUT remove.zeek readd.zeek
# @TEST-EXEC: test ! -f weird.log
#
# @TEST-EXEC: zeek-cut < ssh-default.log > ssh-default.txt && zeek-cut < ssh.log > ssh.txt && cmp ssh-default.txt ssh.txt
# @TEST-EXEC: zeek-cut < conn-default.log > conn-default.txt && zeek-cut < conn.log > conn.txt && cmp conn-default.txt conn.txt
# @TEST-EXEC: btest-diff-cut -m ssh-default.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn-default.log
# @TEST-EXEC: btest-diff-cut -m ssh-removed.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn-removed.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird-removed.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice/weird

# @TEST-START-FILE remove.zeek
redef SSH::kex_methods -= { [/curve25519-sha256.*/] = SSH::KEX_ECC };
# @TEST-END-FILE

# @TEST-START-FILE readd.zeek
redef SSH::kex_methods += { [/curve25519-sha256.*/] = SSH::KEX_ECC };
# @TEST-END-FILE
