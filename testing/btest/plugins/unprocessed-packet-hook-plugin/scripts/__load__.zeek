event packet_not_processed(pkt: pcap_packet)
{
print fmt("packet_not_processed: ts=%d.%d", pkt$ts_sec, pkt$ts_usec);
}