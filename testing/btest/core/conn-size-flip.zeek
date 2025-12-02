# @TEST-DOC: PCAPs contain connections where the ConnSize analyzer counted wrongly.
#
# one-sided-2745: Only contains server packets (syn-ack, ack, fin-ack), but previously originator and responder in conn.log would both have packet counts.
#
# ctu-64702-888: Changed from orig_pkts 9 orig_ip_bytes 384, resp_pkts 7, resp_ip_bytes 306 to
#                             orig_pkts 8 orig_ip_bytes 320, resp_pkts 8, resp_ip_bytes 370
#
# @TEST-EXEC: zeek -C -b -r $TRACES/tcp/one-sided-2745.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes < conn.log > conn.log.one-sided
# @TEST-EXEC: btest-diff conn.log.one-sided
#
# @TEST-EXEC: zeek -C -b -r $TRACES/tcp/ctu-64702-888.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes < conn.log > conn.log.ctu
# @TEST-EXEC: btest-diff conn.log.ctu

@load base/protocols/conn
