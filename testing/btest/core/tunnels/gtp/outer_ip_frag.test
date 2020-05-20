# @TEST-EXEC: zeek -C -r $TRACES/tunnels/gtp/gtp1_gn_normal_incl_fragmentation.pcap
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff tunnel.log

# Normal GTP file, incl. TCP handshake and HTTP message.
# The inner IP packet is put into a GTP tunnel and as the original user payload
# is already 1500 byte, the tunneled packet incl. GTP/UDP/IP payload is
# bigger than 1500 byte and thus the outer IP must be fragmented, as seen here.
# (checksums are incorrect because packets were anonymized and tcprewrite
# seems to fail to correct the checksums when there's IP fragmentation).
