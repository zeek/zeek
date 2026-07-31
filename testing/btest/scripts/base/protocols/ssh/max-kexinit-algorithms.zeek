# @TEST-DOC: Verify the max_kexinit limits work.

# @TEST-EXEC: zcat < $TRACES/ssh/kex-quadratic-1000.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h name addl notice source weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice/weird

redef SSH::max_kexinit_kex_algorithms = 101;
redef SSH::max_kexinit_hostkey_algorithms = 102;
redef SSH::max_kexinit_encryption_algorithms = 103;
redef SSH::max_kexinit_mac_algorithms = 104;
redef SSH::max_kexinit_compression_algorithms = 105;
redef SSH::max_kexinit_languages = 106;
