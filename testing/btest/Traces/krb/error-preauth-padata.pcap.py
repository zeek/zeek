from scapy.all import IP, UDP, Ether, Raw, wrpcap

# LLM Generated explanation of this bytestring:
#
# ASN.1 DER-encoded KRB-ERROR message.
#
# 7e 14          -- [APPLICATION 30] (KRB-ERROR), length 20
#   30 12        -- SEQUENCE, length 18
#     a6 03      -- [6] error-code
#       02 01 19 --   INTEGER 25 (KDC_ERR_PREAUTH_REQUIRED)
#     ac 0b      -- [12] e-data, length 11
#       30 09    --   SEQUENCE (METHOD-DATA / PA-DATA sequence)
#         30 07  --     SEQUENCE (single PA-DATA entry)
#           a1 03  --   [1] padata-type
#             02 01 02 -- INTEGER 2 (PA-ENC-TIMESTAMP)
#           a2 00  --   [2] padata-value, length 0 (EMPTY)
krb = bytes.fromhex("7e143012a603020119ac0b30093007a103020102a200")

pkt = (
    Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    / IP(src="192.0.2.10", dst="192.0.2.20")
    / UDP(sport=55555, dport=88)
    / Raw(load=krb)
)
wrpcap("error-preauth-padata.pcap", pkt)
