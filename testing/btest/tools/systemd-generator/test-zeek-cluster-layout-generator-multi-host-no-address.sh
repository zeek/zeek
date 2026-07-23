# @TEST-DOC: The zeek-cluster-layout-generator pointed at a directory via -C containing three <hostname>.zeek.conf that do not contain address and ensure cluster-layout.zeek contains the blocking_lookup_hostname() calls.
#
# @TEST-REQUIRES: test -x ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator
#
# @TEST-EXEC: ${BUILD}/tools/systemd-generator/zeek-cluster-layout-generator -C $(pwd)/my-cluster -o cluster-layout.zeek
# These use ZEEK_DNS_FAKE instead of going to the system resolver, so that should work.
# @TEST-EXEC: zeek ./cluster-layout.zeek -e 'module Cluster; print "== hosts", hosts' >> out
# @TEST-EXEC: zeek ./cluster-layout.zeek -e 'print "== nodes", Cluster::nodes' >> out
# @TEST-EXEC: btest-diff cluster-layout.zeek
# @TEST-EXEC: btest-diff out

# @TEST-START-FILE my-cluster/c-mgr.zeek.conf
workers = 0
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-1.zeek.conf
manager = 0
loggers = 0
proxies = 0
workers = 2
# @TEST-END-FILE

# @TEST-START-FILE my-cluster/wkr-2.zeek.conf
manager = 0
loggers = 0
proxies = 0
workers = 2
# @TEST-END-FILE
