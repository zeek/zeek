#include "Net.h"
#include "NetVar.h"
#include "TCP.h"
#include "TCP_Reassembler.h"
#include "Sessions.h"
#include "Event.h"
#include "File.h"
#include "Val.h"

// construct
TCPStats_Endpoint::TCPStats_Endpoint(TCP_Endpoint *e, TCPStats_Analyzer *a)
{
  endp = e;
  analyzer = a;

  min_rtt = CONNECTION_RTT_UNKNOWN;
  max_rtt = CONNECTION_RTT_UNKNOWN;
  max_rtt_time = CONNECTION_RTT_UNKNOWN; // time when we saw the max rtt
  min_rtt_time = CONNECTION_RTT_UNKNOWN; // time when we saw the min rtt
  done_syn_ack = 0;

  num_pkts = 0;
  last_id = 0;

  num_rxmit = 0;
  num_rxmit_bytes = 0;
  num_OO = 0;
  num_repl = 0;
  num_gap_events = 0;
  num_gap_bytes = 0;

  max_data_in_flight = -1;

  last_seq_sent = 0;
  max_ack_seq_for_gap_check = 0;
  max_seq_sent = 0;

  last_window_size = -1;

  mss = 0;

  // we initialize these because it's possible that we'll see SYNs but
  // not SYN-ACKs in some connections.  this is a way to see that the
  // syn-ack didn't happen
  syn_size = -1;
  syn_ack_size = -1;

  //  max_top_seq = 0;
  //  endian_type = ENDIAN_UNKNOWN;
}


// destruct
TCPStats_Endpoint::~TCPStats_Endpoint()
{
  loop_over_list(data_in_flight_list, i)
	{
	  delete data_in_flight_list[i];
	}

  loop_over_list(rtt_estimates, j)
	{
	  delete rtt_estimates[j];
	}

  loop_over_list(window_sizes, h)
	{
	  delete window_sizes[h];
	}

  loop_over_list(outstanding_data, l)
	{
	  delete outstanding_data[l];
	}

  IterCookie* c = expected_acks.InitForIteration();
  Packet_Statistics *p;
  HashKey *k;

  while ( (p = (Packet_Statistics *)(expected_acks.NextEntry(k, c, 1))) ) {
	delete p;
	delete k;
  }
}


// This method checks for:
// 1. replay packets
// 2. out-of-order packets
// It does NOT do retransmissions; see below
void TCPStats_Endpoint::CheckOutOfOrder(uint32 ip_id, uint32 seq, bool is_syn, bool is_fin)
{
  // first packet
  if (NumPackets() == 1)
	return;

  // ignore SYN and FIN retransmits
  if (is_syn || is_fin)
	return;

  // previous ip id
  uint32 last_id = LastID();
  // previous sequence number.  we do want LastSeqSent() here, not
  // LastSeq().  for one, LastSeq() is updated before this gets
  // called, so it will always be equal to seq.  but LastSeq() also
  // doesn't handle retransmissions in the same way as LastSeqSent()
  // does, and i *believe* we want the latter
  uint32 last_seq = LastSeqSent();
  
  // inter-arrival time
  float iat = current_timestamp - LastPacketTimestamp();

  // same ip id, same sequence numbers
  if (ip_id == last_id && seq == last_seq) {

	// inter-arrival time is less than the median rtt; this is likely
	// a replay packet
	if (iat < min_rtt) {

	  RecordReplay();
	  
	  if (!ignore_tcp_events) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_timestamp, TYPE_DOUBLE));
		vl->append(new Val(seq, TYPE_COUNT));
		vl->append(new Val(IsOrig(), TYPE_BOOL));
	  
		analyzer->ConnectionEvent(tcp_replay, vl);
	  }

	  // if this were false, we want to flag this as a retransmission.
	  // that check happens in insertsequencenumber, though, so we
	  // won't repeat it here.
	  //
	  // TODO: it would really be cleaner, in some sense, to do it
	  // here, but insertsequencenumber needs some information about
	  // retransmissions.
	}
  }

  // don't check for out-of-order SYNs.  if we've made it to here and
  // we have a SYN, it's a retransmitted SYN (since we ignore the
  // first packet)
  if (!is_syn) {

	short id_delta = ip_id - last_id;
	short id_endian_delta = endian_flip(ip_id) - endian_flip(last_id);

	int abs_id_delta = id_delta > 0 ? id_delta : -id_delta;
	int abs_id_endian_delta = id_endian_delta > 0 ? id_endian_delta : -id_endian_delta;

	int final_id_delta;
	
	// Consistent with big-endian.
	if ( abs_id_delta < abs_id_endian_delta )
	  final_id_delta = id_delta;
	// Consistent with little-endian.
	else
	  final_id_delta = id_endian_delta;

	// TODO: why -256?
	// TODO: this code confuses me in general

	if ((final_id_delta < 0 && final_id_delta > -256) && 	  // If we see the IP ID decrease *and* the sequence number decreases..
		Sequence_number_comparison(last_seq, seq) > 1 &&
		!ignore_tcp_events) {

	  RecordOutOfOrder();

	  val_list *vl = new val_list;
	  vl->append(analyzer->BuildConnVal());
	  vl->append(new Val(current_timestamp, TYPE_DOUBLE));
	  vl->append(new Val(seq, TYPE_COUNT));
	  vl->append(new Val(IsOrig(), TYPE_BOOL));
	  analyzer->ConnectionEvent(tcp_out_of_order, vl);
	}
  }
}

float TCPStats_Endpoint::GetIAT(uint32 seq)
{
  float iat = -1.0;

  IterCookie* c = expected_acks.InitForIteration();
  Packet_Statistics *p;
  HashKey *k;

  uint32 min_seq = 0;
  double t = 0.0;
  while ( (p = (Packet_Statistics *)(expected_acks.NextEntry(k, c, 1))) ) {
	if (p->SeqToInsert() > seq &&
		(t == 0.0 || min_seq > p->SeqToInsert())) {
	  min_seq = p->SeqToInsert();
	  t = p->PacketSentTimestamp();
	}

	delete k;
  }

  expected_acks.StopIteration(c);

  if (t != 0.0)
	iat = current_timestamp - t;

  return iat;
}


// first "real" method.  inserts sequence number -> packet mapping into our dictionary
void TCPStats_Endpoint::InsertSequenceNumber(Seq_Range *seq, Packet_Statistics *value, bool is_window_probe)
{
  uint32 seq_to_ack = seq->to_ack;
  HashKey *h = new HashKey((bro_uint_t) seq_to_ack);
  // the previous value for this sequence number, if any
  Packet_Statistics *prev_value = (Packet_Statistics *) expected_acks.Lookup(h);
  // last sequence number set
  uint32 max_seq = MaxSeqSent();
  uint32 max_ack = MaxAckSeqForGapCheck() - StartSeq();

  double iat = GetIAT(seq_to_ack);

  // three cases, in increasing level of annoyance:
  // 1. we've already seen sequence number s and it hasn't been acked.
  //    => s in expected_acks
  // 2. we've already seen sequence number s and it has been acked.
  //    => s not in expected_acks
  //    => max_ack'ed >= s
  // 3. we've never seen s, but this isn't a re-ordering
  //    => s not in expected_acks
  //    => max_seq >= s (otherwise it's not out-of-order) && iat > min_rtt (otherwise it's reordering)

  if ((prev_value ||
	   (max_seq >= seq_to_ack && max_ack >= seq_to_ack) ||
	   (max_seq >= seq_to_ack && iat > min_rtt))) {

	// *don't* throw events on window probes
	if (!is_window_probe) {

	  // set our new value as a rtx, throw the event
	  value->SetAsRTX();
	  RecordRetransmission(value->PacketSize());

	  double delay_time;
	  if (prev_value)
		delay_time = current_timestamp - prev_value->PacketSentTimestamp();
	  else
		delay_time = current_timestamp - LastPacketTimestamp();

	  ThrowRTXEvent(current_timestamp, seq->to_ack, delay_time, value->IsSYN());
	}

	// result is going to point to the same place as prev_value.  this just allows us to also delete the key in the dict
	Packet_Statistics *result = RemoveSequenceNumber(seq_to_ack);
	delete result;
  }

  // insert it into the dict..
  expected_acks.Insert(h, value);
  delete h; // TODO: this shouldn't work..

  // ..and into our pseudo keyset
  if (!outstanding_data.is_member(seq, Reverse_sequence_range_comparison)) // want a set, not a list
  	outstanding_data.sortedinsert(seq, Reverse_sequence_range_comparison);
  else
  	delete seq;
}

// second real method.  removes packet from our dictionary, while also throwing some events (perhaps)
Packet_Statistics* TCPStats_Endpoint::SetPacketACKTimeAndGetSummary(uint32 seq, double timestamp)
{
  bool was_rtx = false;

  uint32 prev_max = MaxAckSeqForGapCheck() - StartSeq();
  Packet_Statistics *packet = NULL;

  // calling get() on lists removes data; that's why there is no
  // explicit delete from outstanding_data
  Seq_Range *range_key = outstanding_data.get();

  // 1. remove the now-acked packets from the dict
  // 2. check if any of those packets were retransmits
  // 3. check if any of those packets caused a gap

  while (range_key && Sequence_number_comparison(range_key->to_ack, seq) < 1) {

	// delete previous packet
	if (packet)
	  delete packet;

	// get the next packet.  this will also remove the data from
	// expected_acks (the call to get() is where it gets removed from
	// outstanding_data)
	packet = RemoveSequenceNumber(range_key->to_ack);

	// check for retransmits
	if (packet->IsRTX())
	  was_rtx = true;

	// check for gaps.  checking between the last sequence number we saw and the one in range_key
	//
	// gaps occur when we see an ack for seq # s, but of the data
	// being sent up to s, some of it has not been seen.  so if we see
	// a range_key with min greater than the max of the previous one
	// (e.g., [1, 3] [5, 6]), there was a gap.

	if (Sequence_number_comparison(range_key->min, prev_max) == 1 && !packet->IsSYN()) {
	  ThrowGapEvent(seq, prev_max, range_key->min-1); // range_key->min is what we wanted ACKed, so the gap is actually to a sequence number one less
	}

	prev_max = range_key->to_ack;

	delete range_key;
	range_key = outstanding_data.get();
  }

  // whether we delete the range key at the end (we almost always do)
  bool delete_range_key = true;

  // check the last gap.  checking between the last sequence number we
  // saw and the one we're adding.  see above call to ThrowGapEvent
  // for explanation of gaps.
  //
  // the !packet at the end checks for the case when the gap occurs at
  // the very end.  for instance: sequence numbers [1 3][4 5], ack for
  // 7
  //
  // the MaxAckSeqForGapCheck() at the beginning eliminates throwing
  // gaps when early packets get lost and we missed a handshake (see
  // lost-gap.pcap)
  if (MaxAckSeqForGapCheck() != 0 &&
	  Sequence_number_comparison(prev_max, seq) == -1 &&
	  ((packet && !packet->IsSYN()) || !packet)) {
	ThrowGapEvent(seq, prev_max, seq);
  }

  // put the key back in if it wasn't the one we wanted (i.e., it was
  // too high), set packet to null so we don't use it
  if (range_key && range_key->to_ack != seq) {
	outstanding_data.sortedinsert(range_key, Reverse_sequence_range_comparison);
	delete_range_key = false;
	// TODO: why do we not re-insert packet?
	delete packet;
	packet = NULL;
  }

  // this packet spans a retransmit; we want to ignore the estimate entirely (i.e., don't even return it)
  if (was_rtx) {
	delete packet;
	if (delete_range_key)
	  delete range_key;
	packet = NULL;
  }

  if (packet) {

	packet->SetAckReceivedTime(timestamp);

	// ignore RTTs from syns and fins for our purposes, but return
	// them so that the stats analyzer can use them for determining
	// the measurement vantage point
	if (!packet->IsFIN() && !packet->IsSYN()) {
	  UpdateRTTStats(new double(packet->RTT()), packet->PacketSentTimestamp());
	  ThrowConnRTTEvent(packet->PacketSentTimestamp(), packet->RTT(), seq, packet->PacketSize(), packet->IsSYN());
	}
  }
  
  if (range_key && delete_range_key)
	delete range_key;

  return packet;

}

// actual remove function for dict (gets its own function because we have to make a hashkey out of a sequence number)
Packet_Statistics* TCPStats_Endpoint::RemoveSequenceNumber(uint32 seq)
{
  HashKey *h = new HashKey((bro_uint_t) seq);

  // Remove will delete the key
  Packet_Statistics *result = (Packet_Statistics *) expected_acks.Remove(h);
  delete h;

  return result;
}


RecordVal* TCPStats_Endpoint::BuildStats()
{
  RecordVal* stats = new RecordVal(endpoint_stats);

  stats->Assign(0, new Val(num_pkts,TYPE_COUNT));
  stats->Assign(1, new Val(num_rxmit,TYPE_COUNT));
  stats->Assign(2, new Val(num_rxmit_bytes,TYPE_COUNT));
  stats->Assign(3, new Val(num_OO,TYPE_COUNT));
  stats->Assign(4, new Val(num_repl,TYPE_COUNT));
  stats->Assign(5, new Val(num_gap_events, TYPE_COUNT));
  stats->Assign(6, new Val(num_gap_bytes, TYPE_COUNT));
  stats->Assign(7, new Val(max_data_in_flight, TYPE_COUNT));

  return stats;
}

void TCPStats_Endpoint::CheckOutstandingData()
{
  // if we haven't yet sent any data, we're not going to report
  // outstanding data (without this, if we see sequences of SYNs and
  // RSTs, those will get reported as 1 outstanding byte of data)
  if (endp->State() == TCP_ENDPOINT_SYN_SENT ||
	  endp->State() == TCP_ENDPOINT_SYN_ACK_SENT)
	return;

  // this was the endpoint that *caused* the reset; we don't want to
  // check it for outstanding data.  without this statement, the RST
  // packet itself will show up as un-acked data.
  if (endp->State() == TCP_ENDPOINT_RESET)
	return;

  // number of outstanding bytes (last sequence sent vs. the one that was just acked)
  int outstanding = LastSeq() - AckSeq();

  if (outstanding > 0 && !ignore_tcp_events) {

	val_list *vl = new val_list;
	vl->append(analyzer->BuildConnVal());
	vl->append(new Val(network_time, TYPE_DOUBLE));
	vl->append(new Val(outstanding, TYPE_INT));
	vl->append(new Val(IsOrig(), TYPE_BOOL));

	analyzer->ConnectionEvent(tcp_outstanding_data, vl);
  }
}

RecordVal* TCPStats_Endpoint::GetFlightSummary()
{
  RecordVal *stats = NULL;

  if (data_in_flight_list.length() > 0) {

	stats = new RecordVal(flight_stats);
	stats->Assign(0, new Val(Mean(data_in_flight_list), TYPE_DOUBLE));
	stats->Assign(1, new Val(int(Median(data_in_flight_list)), TYPE_INT));
	stats->Assign(2, new Val(int(LowerQuartile(data_in_flight_list)), TYPE_INT));
	stats->Assign(3, new Val(int(UpperQuartile(data_in_flight_list)), TYPE_INT));
	stats->Assign(4, new Val(int(Min(data_in_flight_list)), TYPE_INT));
	stats->Assign(5, new Val(int(Max(data_in_flight_list)), TYPE_INT));
  }

  return stats;
}

RecordVal* TCPStats_Endpoint::GetWindowSummary()
{
  RecordVal *stats = NULL;

  if (window_sizes.length() > 0) {
	stats = new RecordVal(window_stats);
	stats->Assign(0, new Val(int(Median(window_sizes)), TYPE_INT));
	stats->Assign(1, new Val(0, TYPE_INT));
	stats->Assign(2, new Val(0, TYPE_INT));
	stats->Assign(1, new Val(int(Min(window_sizes)), TYPE_INT));
	stats->Assign(2, new Val(int(Max(window_sizes)), TYPE_INT));
  }

  return stats;
}

RecordVal *TCPStats_Endpoint::GetRTTSummary()
{
  RecordVal *stats = new RecordVal(rtt_stats);
  stats->Assign(0, new Val(Mean(rtt_estimates), TYPE_DOUBLE));
  stats->Assign(1, new Val(Median(rtt_estimates), TYPE_DOUBLE));
  stats->Assign(2, new Val(LowerQuartile(rtt_estimates), TYPE_DOUBLE));
  stats->Assign(3, new Val(UpperQuartile(rtt_estimates), TYPE_DOUBLE));
  stats->Assign(4, new Val(min_rtt, TYPE_DOUBLE));
  stats->Assign(5, new Val(min_rtt_time, TYPE_DOUBLE));
  stats->Assign(6, new Val(max_rtt, TYPE_DOUBLE));
  stats->Assign(7, new Val(max_rtt_time, TYPE_DOUBLE));


  return stats;
}

// pre-condition: call HasRTTEstimates *before* calling this.
double TCPStats_Endpoint::MedianRTT()
{
  return Median(rtt_estimates);
}


double Min(PList(double) list)
{
  bool min_set = false;
  double min;

  loop_over_list(list, i)
	{
	  double value = *(list[i]);
	  if (!min_set || value < min) {
		min = value;
		min_set = true;
	  }
	}
  return min;
}

double Max(PList(double) list)
{
  bool max_set = false;
  double max;

  loop_over_list(list, i)
	{
	  double value = *(list[i]);
	  if (!max_set || value > max) {
		max = value;
		max_set = true;
	  }
	}
  return max;
}

double LowerQuartile(PList(double) list)
{
  return GetPercentile(list, 25);
}

double UpperQuartile(PList(double) list)
{
  return GetPercentile(list, 75);
}

double Median(PList(double) list)
{
  return GetPercentile(list, 50);
}

double GetPercentile(PList(double) list, int p)
{
  double position = list.length() * (p/100.0);

  if ((int) position == position)
	return GetNthElement((int) position, list);
  else
	return GetNthElement((int) position + 1, list);
}

// returns the nth element in a list.  precondition: list->length() > 0
double GetNthElement(int n, PList(double) list_arg)
{
  // pick a pivot element
  double pivot = *(list_arg[int(list_arg.length()/2)]);

  // lists to keep track of elements < pivot, > pivot
  PList(double) bottom_half;
  PList(double) top_half;

  // append each element to the appropriate list
  loop_over_list(list_arg, i)
	{
	  if (*(list_arg[i]) > pivot)
		top_half.append(list_arg[i]);
	  else if (*(list_arg[i]) < pivot)
		bottom_half.append(list_arg[i]);
	}

  double to_return;

  int n1 = bottom_half.length();
  int n2 = top_half.length();

  // note that n1 + n2 <= list->length(); not equal to. we could have
  // multiple instances of the pivot's value. that is what makes the
  // below cases slightly more complicated
  if (n1 == n-1 || (n1 < n-1 && n2 <= list_arg.length() - n))
	to_return = pivot;
  else if (n1 < n)
	to_return = GetNthElement(n - (list_arg.length() - n2), top_half);
  else
	to_return = GetNthElement(n, bottom_half);

  top_half.clear();
  bottom_half.clear();
	
  return to_return;
}

double Mean(PList(double) list) {

  int n = list.length();

  double sum = 0.0;
  loop_over_list(list, i)
  	{
	  sum += *(list[i]);
  	}

  return sum/n;
}

void TCPStats_Endpoint::ThrowConnRTTEvent(double timestamp, double rtt, uint32 seq, int len, bool is_syn)
{

  if (ignore_rtt_events)
	return;

  val_list *vl = new val_list;
  vl->append(analyzer->BuildConnVal());
  vl->append(new Val(timestamp, TYPE_DOUBLE));
  vl->append(new Val(rtt, TYPE_DOUBLE));
  vl->append(new Val(seq, TYPE_COUNT));
  vl->append(new Val(len, TYPE_INT));
  vl->append(new Val(is_syn, TYPE_BOOL));
  vl->append(new Val(endp->is_orig, TYPE_BOOL));

  analyzer->ConnectionEvent(conn_rtt, vl);
}

void TCPStats_Endpoint::ThrowGapEvent(uint32 ack_seq, uint32 gap_min, uint32 gap_max)
{
  if (ignore_tcp_events)
	return;

  // don't throw this.  it happens when we see connections w/o a handshake
  if (ack_seq == 1 || gap_max == 0)
	return;

  // TODO: this is not going to handle wrap-around
  RecordGap(gap_max - gap_min);

  val_list *vl = new val_list;
  vl->append(analyzer->BuildConnVal());
  vl->append(new Val(current_timestamp, TYPE_DOUBLE));
  vl->append(new Val(ack_seq, TYPE_COUNT));
  vl->append(new Val(gap_min, TYPE_COUNT));
  vl->append(new Val(gap_max, TYPE_COUNT));
  vl->append(new Val(IsOrig(), TYPE_BOOL));
	  
  analyzer->ConnectionEvent(tcp_ack_above_gap, vl);
}

// this will thrown 1 + sequence number on FIN retransmissions (and I think SYNs too)
void TCPStats_Endpoint::ThrowRTXEvent(double timestamp, uint32 seq, double delay_time, bool is_syn)
{

  if (ignore_tcp_events)
	return;

  val_list* vl = new val_list();
  vl->append(analyzer->BuildConnVal());
  vl->append(new Val(timestamp, TYPE_DOUBLE));
  vl->append(new Val(seq, TYPE_COUNT));
  vl->append(new Val(delay_time, TYPE_DOUBLE));
  vl->append(new Val(IsOrig(), TYPE_BOOL));
  vl->append(new Val(is_syn, TYPE_BOOL));

  analyzer->ConnectionEvent(tcp_retransmission, vl);
}

// timestamp = when the packet was *sent*, not when the ack was received
void TCPStats_Endpoint::UpdateRTTStats(double *new_rtt, double timestamp)
{
  if (min_rtt == CONNECTION_RTT_UNKNOWN || *new_rtt < min_rtt) {
	min_rtt = *new_rtt;
	min_rtt_time = timestamp;
  }

  if (max_rtt == CONNECTION_RTT_UNKNOWN || *new_rtt > max_rtt) {
	max_rtt = *new_rtt;
	max_rtt_time = timestamp;
  }

  rtt_estimates.append(new_rtt);
}

//int TCPStats_Endpoint::DataSent(double t, int seq, int len, int caplen,
//								const u_char* /* data */,
//								const IP_Hdr* ip, const struct tcphdr* /* tp */)
/*{

  if ( ++num_pkts == 1 ) {
	// First packet.
	last_id = ntohs(ip->ID4());
	return 0;
  }

  int id = ntohs(ip->ID4());
  
  if ( id == last_id ) {
	++num_repl;
	return 0;
  }

  short id_delta = id - last_id;
  short id_endian_delta = endian_flip(id) - endian_flip(last_id);

  int abs_id_delta = id_delta > 0 ? id_delta : -id_delta;
  int abs_id_endian_delta =
	id_endian_delta > 0 ? id_endian_delta : -id_endian_delta;

  int final_id_delta;
	
  if ( abs_id_delta < abs_id_endian_delta ) {
	// Consistent with big-endian.
	if ( endian_type == ENDIAN_UNKNOWN )
	  endian_type = ENDIAN_BIG;
	else if ( endian_type == ENDIAN_BIG )
	  ;
	else
	  endian_type = ENDIAN_CONFUSED;
	
	final_id_delta = id_delta;
  }
  else {
	// Consistent with little-endian.
	if ( endian_type == ENDIAN_UNKNOWN )
	  endian_type = ENDIAN_LITTLE;
	else if ( endian_type == ENDIAN_LITTLE )
	  ;
	else
	  endian_type = ENDIAN_CONFUSED;
	
	final_id_delta = id_endian_delta;
  }
  
  if ( final_id_delta < 0 && final_id_delta > -256 ) {
	++num_OO;
	return 0;
  }

  last_id = id;

  ++num_in_order;

  int top_seq = seq + len;

  max_top_seq = top_seq;

  // Removed out-of-order packet processing from here
  
  return 0;
}*/

int Reverse_sequence_range_comparison(const void *v1, const void *v2)
{

  const Seq_Range *r1 = (const Seq_Range*) v1;
  const Seq_Range *r2 = (const Seq_Range*) v2;

  // for now, just compare based on the ack sequence number.  should be fine..
  // TODO: this baffles me.  why does this work for reverse?
  int to_return = 0;
  if (r1->to_ack < r2->to_ack)
	to_return = -1;
  else if (r1->to_ack - r2->to_ack > SEQ_SPACE_THRESHOLD)
	to_return = -1;
  else if (r1->to_ack > r2->to_ack)
	to_return = 1;

  return to_return;
}
