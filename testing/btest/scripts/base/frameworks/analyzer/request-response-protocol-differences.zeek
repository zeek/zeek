# This test checks behavior when the originator and responder protocols
# differ - e.g. when a HTTPS client connects to a HTTP port.
#
# @TEST-EXEC: zeek -r ${TRACES}/http/http-to-ssh.pcap
# @TEST-EXEC: mv conn.log conn-http-to-ssh.log
# @TEST-EXEC: zeek -r ${TRACES}/tls/https-to-http.pcap
# @TEST-EXEC: mv conn.log conn-https-to-http.log
# @TEST-EXEC: btest-diff conn-http-to-ssh.log
# @TEST-EXEC: btest-diff conn-https-to-http.log

