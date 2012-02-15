
#ifndef tcpstatsendpoint_h
#define tcpstatsendpoint_h

#define PACKET_RTT_UNKNOWN -1.0

struct Seq_Range {
  uint32 min;
  uint32 max;
  uint32 to_ack; // will almost always be equal to max
};

class Packet_Statistics;
class TCPStats_Analyzer;

declare(PList, uint32);
declare(PList, double);
declare(PList, Seq_Range);

enum SummaryType { RTT_SUMMARY };


// holds some statistics about a packet, including its size, time
// sent, and time the ack was received.  we use this when keeping track
// of packets for which we expect to see acks, and hence for packets for
// which we want to calculate the rtt.
class Packet_Statistics {
 public:
  Packet_Statistics(double t, int s, uint32 seq) {
	packet_sent_timestamp = t;
	//	printf("timestamp: %f\n", packet_sent_timestamp);
	packet_size = s;
	ack_received_timestamp = PACKET_RTT_UNKNOWN;
	is_rtx = false;
	is_fin = false;
	is_syn = false;
	seq_to_insert = seq;
  }

  void SetAckReceivedTime(double t) { ack_received_timestamp = t; }
  double RTT() { return ack_received_timestamp - packet_sent_timestamp; }
  int PacketSize() { return packet_size; }
  double PacketSentTimestamp() { return packet_sent_timestamp; }
  void SetAsRTX() { is_rtx = 1; }
  bool IsRTX() { return is_rtx; }

  void SetAsFIN() { is_fin = 1; }
  void SetAsSYN() { is_syn = 1; }
  bool IsFIN() { return is_fin; }
  bool IsSYN() { return is_syn; }

  uint32 SeqToInsert() { return seq_to_insert; }

 protected:
  double packet_sent_timestamp;
  double ack_received_timestamp;
  int packet_size;
  uint32 seq_to_insert;
  bool is_rtx;
  bool is_fin;
  bool is_syn;
};


class TCPStats_Endpoint {
public:
  TCPStats_Endpoint(TCP_Endpoint *e, TCPStats_Analyzer *a);
  ~TCPStats_Endpoint();

  RecordVal* BuildStats();

  // 1. inserts the mapping: seq -> packet_statistics
  // 2. checks and records retransmits.  throws event if appropriate.
  void InsertSequenceNumber(Seq_Range *seq, Packet_Statistics *value, bool is_window_probe);

  // 1. cleans up the dictionary (removes packets that have now been acked)
  // 2. throws gap events
  // 3. throws conn_rtt events
  Packet_Statistics *SetPacketACKTimeAndGetSummary(uint32 seq, double timestamp);

  // summaries, for events
  RecordVal* GetFlightSummary();
  RecordVal* GetRTTSummary();
  RecordVal* GetWindowSummary();
  
  // wrappers for functions of TCP_Endpoint
  uint32 StartSeq() const { return endp->StartSeq(); }
  uint32 LastSeq() { return endp->LastSeq(); }
  uint32 AckSeq() { return endp->AckSeq(); }

  // last sequence number sent including retransmissions. not the
  // same as LastSeq()
  uint32 LastSeqSent() { return last_seq_sent; }
  void UpdateLastSeqSent(uint32 seq) { last_seq_sent = seq; }

  // TODO: this doesn't deal with seq num wrap
  uint32 MaxSeqSent() { return max_seq_sent; }
  void UpdateMaxSeqSent(uint32 seq) { max_seq_sent = seq; }

  // this *almost* mirrors AckSeq() except it gets updated by
  // TCPStats_Analyzer, not TCP_Analyzer.  it's only used for checking acks
  // above a gap, hence the name.
  // TODO: this is not the cleanest thing in the world..
  // TODO: i'm also using it for out-of-order checks
  uint32 MaxAckSeqForGapCheck() { return max_ack_seq_for_gap_check; }
  void UpdateMaxAckSeqForGapCheck(uint32 arg) { max_ack_seq_for_gap_check = arg; }

  float GetIAT(uint32 seq);

  // whether we have seen an ack for our syn.  NOTE: it's checking
  // for an ack for the syn, not necessary a syn-ack (as in a 3-way
  // handshake); i.e., we still use it for simultaneous connections
  // (syn syn ack ack vs. syn syn-ack ack).
  bool DoneSYNACK() { return done_syn_ack; } 
  void SetDoneSYNACK(bool value) { done_syn_ack = value; }

  uint32 SYNACKSize() { return syn_ack_size; }
  void SetSYNACKSize(uint32 size) { syn_ack_size = size; }

  uint32 SYNSize() { return syn_size; }
  void SetSYNSize(uint32 arg) { syn_size = arg; }

  // last IP ID seen
  void SetLastID(int id) { last_id = id; }
  int LastID() { return last_id; }

  // timestamp of last packet sent
  double LastPacketTimestamp() { return last_packet_timestamp; }
  void UpdateLastPacketTimestamp(double t) { last_packet_timestamp = t; }

  // to check before we throw an event (don't throw if we don't have any data)
  bool HasRTTEstimates() {return rtt_estimates.length() > 0; }
  bool HasWindowSizes() { return window_sizes.length() > 0; }

  int numOutstandingPackets() { return outstanding_data.length(); }

  // TTL that this endpoint sees.  used by stats analyzer to estimate measurement vantage point
  int TTL() { return ttl; };
  void SetTTL(int ttl_arg) { ttl = ttl_arg; }

  // if this endpoint is the origin
  bool IsOrig() { return is_orig; }
  void SetIsOrig(bool arg) { is_orig = arg; }

  int WindowScale() { return endp->window_scale; }

  void SetMSS(int arg) { mss = arg; }
  int MSS() { return mss; }

  // record some data points
  void RecordDataInFlight(double *data_in_flight) {
	data_in_flight_list.append(data_in_flight);
	if (*data_in_flight > max_data_in_flight)
	  max_data_in_flight = (int) *data_in_flight;
  }
  void RecordReplay() { num_repl++; }
  void RecordRetransmission(int len) { num_rxmit++; num_rxmit_bytes+=len; }
  void RecordOutOfOrder() { num_OO++; }

  // TODO: all of the PLists should be recorded this way, instead of
  // creating the pointers in TCPStats_Endpoint.cc
  void RecordWindowSize(int window) {
	double *window_p = new double;
	*window_p = window;
	window_sizes.append(window_p);
	last_window_size = window;
  }

  void RecordGap(int gap_size) { num_gap_events++; num_gap_bytes += gap_size; }
  void UpdateRTTStats(double *new_rtt, double timestamp);

  int GetLastWindowSize() { return last_window_size; }

  int MaxDataInFlight() { return max_data_in_flight; }

  void IncrementPacketCount() { num_pkts++; }
  int NumPackets() { return num_pkts; }

  // check if we have outstanding data.  tcpstats_analyzer calls this
  void CheckOutstandingData();

  void CheckOutOfOrder(uint32 ip_id, uint32 seq, bool is_syn, bool is_fin);

  // this gets its own method, because TCP.cc needs to have access to the median RTT for peers
  double MedianRTT();

protected:

  int num_pkts;
  int num_rxmit;
  int num_rxmit_bytes;
  int num_OO;
  int num_repl;
  int last_id;

  int num_gap_events;
  int num_gap_bytes;

  int max_data_in_flight;

  double last_packet_timestamp;

  //	int max_top_seq;
  //	int endian_type;

  // associate with a TCPStats_Analyzer so that we can throw events ourselves
  TCPStats_Analyzer *analyzer;
  // associate with a TCP_Endpoint so that we have access to the state machine
  TCP_Endpoint *endp;

  // whether this endpoint is the origin
  bool is_orig;

  bool done_syn_ack;
  uint32 last_seq_sent, max_ack_seq_for_gap_check, max_seq_sent;
  int ttl, mss;

  int last_window_size;

  // size of SYN packet.  unfortunately we need this data after we've
  // already seen the syn, hence keeping this variable around
  uint32 syn_size;
  // same problem
  uint32 syn_ack_size;

  // keeps track of the sequence numbers for which we expect ACKs.
  // sequence number maps to a Packet_Statistics object, which has the time
  // the packet was sent, among many other things.
  Dictionary expected_acks;

  // basically the key set for expected_acks, just sorted, and comes with ranges. (so really not the key set at all.)
  PList(Seq_Range) outstanding_data;

  // lists of data
  PList(double) rtt_estimates;
  // TODO: really, these should both be PLists of ints
  PList(double) window_sizes;
  PList(double) data_in_flight_list;

  // we keep the min and max rtt explicitly, because we also want
  // times to be associated with those
  double min_rtt, max_rtt;
  double min_rtt_time, max_rtt_time;

  // remove from our dict
  Packet_Statistics *RemoveSequenceNumber(uint32 seq);

 private:

  // events we throw
  void ThrowRTXEvent(double timestamp, uint32 seq, double delay_time, bool is_syn);
  void ThrowGapEvent(uint32 ack_seq, uint32 gap_min, uint32 gap_max);
  void ThrowConnRTTEvent(double timestamp, double rtt, uint32 seq, int len, bool is_syn);
};

// TODO: should overload to take ints, or something..
double Mean(PList(double) list);
double Median(PList(double) list);
double LowerQuartile(PList(double) list);
double UpperQuartile(PList(double) list);
double GetPercentile(PList(double) list, int p);
double Min(PList(double) list);
double Max(PList(double) list);

// returns the nth element in a list.  precondition: list->length() > 0
double GetNthElement(int n, PList(double) list_arg);


#endif
