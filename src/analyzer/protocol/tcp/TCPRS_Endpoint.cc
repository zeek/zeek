/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */

#include "Net.h"
#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Sessions.h"
#include "Event.h"
#include "analyzer/protocol/tcp/events.bif.h"
#include "File.h"
#include "Val.h"
#include "Discard.h"
#include <cstdarg>

#include "analyzer/protocol/tcp/TCPRS_Endpoint.h"
#include "analyzer/protocol/tcp/TCPRS_Debug.h"

#define SEQUENCE_MAX 4294967295ull
#define STDEV_UNIFORM 0.68
#define LOW_CONFIDENCE_THRESH 0.25

using namespace analyzer::tcp;

//Valgrind Safe
TCPRS_Endpoint::TCPRS_Endpoint(tcp::TCP_Endpoint *e, tcp::TCPRS_Analyzer *a) {
	endp = e;
	analyzer = a;

	doneSynAck = 0;

	numRTO = 0;      //Number of times that the RTO caused a rxmit
	numFastRTX = 0; //Number of times that fast rtx was initiated
	numSlowStart = 0; //Number of times that slow start was initiated due to congestion
	segmentCount = 0;
	numDuplicateAcks = 0;  //Number of times that duplicate acks were seen
	numOutOfOrder = 0; //Number of times that a packet was out of order on the
					   //  the way to this endpoint

	lastIPID = 0;
	numRexmit = 0;
	numRexmitBytes = 0;

	maxDataInFlight = -1;

	lastSequenceSent = 0;
	lastAckSeqForGapCheck = 0;

	mss = 0;
	highestAcknowledgement = 0;
	highestSequence = 0;
	stateConfidence = 0;

	congestionState = CONGESTION_UNKNOWN;
	previousCongestionState = CONGESTION_UNKNOWN;
	prevWindow = 0;

	minRTT = UNDEFINED;

	responseState = RSTATE_ENDPOINT_ALIVE;
	deadSegmentCount = 0;
	deadConnectionDuration = 0;
	prevOutstanding = 0;
	lastWindowSampleTS = 0;

	usesTimestamps = false;
	checkedForTSOptions = false;
	currentTSVal = 0;
	memset((void*) &deltaOutstandingData, 0, sizeof(ODRate));
	memset((void*) &endpointGapInfo, 0, sizeof(GapInfo));

	deltaOutstandingData.rtx_timestamp = UNDEFINED;

	endpointGapInfo.timestamp = network_time;
	endpointGapInfo.roundtrip = UNDEFINED;

	recoveryState = RECOVERY_NORMAL;

	usesDelayedAcks = false;
	rttNumValidSamples = 0;
	SACKEnabled = false;
	rtt = UNDEFINED;
	rttvar = UNDEFINED;
	estimatedRTO = 3.0;
	sackedBytes = 0;
	sackedSegments = 0;

	recoverySequence = 0;

	fackCount = 0;
	ackCount = 0;
	for (int i = 0; i < ACK_COUNT; i++) {
		fackTimestamps[i] = 0;
		ackTimestamps[i] = 0;
	}
	maximumRTO = UNDEFINED;
	lastRetransmissionSeq = 0;
	lastRetransmissionTS = UNDEFINED;
	lastRetransmissionRTO = false;
	lastSegmentRetransmitted = false;

	sendTimestampVal = 0;
	echoTimestampVal = 0;

	deadConnectionDiedTS = UNDEFINED;
	deadConnectionDuration = UNDEFINED;
}

//Valgrind Safe
// destruct
TCPRS_Endpoint::~TCPRS_Endpoint() {
	loop_over_list(outstandingData, l) {
		delete outstandingData[l];
	}
	loop_over_list(timeouts, a) {
		delete timeouts[a];
	}
	loop_over_list(acks, f) {
		delete acks[f];
	}
	loop_over_list(dsacks, g) {
		delete dsacks[g];
	}
	loop_over_list(rexmits, h) {
		delete rexmits[h];
	}

	IterCookie* c = expectedAcks.InitForIteration();
	Segment *p;
	HashKey *k;

	IterCookie* d = duplicateAcknowledgments.InitForIteration();
	DuplicateAck* iter;
	HashKey *z;

	while ((iter =
			(DuplicateAck *) (duplicateAcknowledgments.NextEntry(z, d, 1)))) {
		delete iter;
		delete z;
	}

	while ((p = (Segment *) (expectedAcks.NextEntry(k, c, 1)))) {
		delete p;
		delete k;
	}

}

void TCPRS_Endpoint::DeliverSegment(int len, const u_char* data,
		bool is_orig, int seq, const IP_Hdr* ip, int caplen) {
	ASSERT(ip->Payload());

	const struct tcphdr* tp = (const struct tcphdr*) ip->Payload(); //TODO: this is a hack. Fix it.

	TCP_Flags flags(tp);
	SegmentInfo *p;

	/* process this now only if it is not an ACK or if we don't have an
	 estimate on the RTT
	 */
	/*int process_now = !(hasPathRTTEstimate() && flags.ACK());

	 if (!queued_packets.empty()){
	 p = queued_packets.front();
	 while ( !queued_packets.empty() && (network_time > p->time_to_process)) {
	 printf("processing %f at %f\n", p->time_to_process, network_time);
	 ProcessPacket(p);
	 queued_packets.pop();
	 delete[] p->tp;
	 delete p;
	 p = queued_packets.front();
	 }
	 }*/

	p = new SegmentInfo;
	ASSERT(p);

	p->current_time = current_timestamp; // This call makes the analyzer re-entrant
	p->len = len;
	p->segmentID = ip->ID();
	p->ttl = ip->TTL();

	p->tp = (u_char*) tp;
	ProcessSegment(p);
	delete p;
}

void TCPRS_Endpoint::ProcessSegment(SegmentInfo *segment) {
	const struct tcphdr* tp = (const struct tcphdr*) segment->tp;
	TCP_Flags flags((const struct tcphdr*) segment->tp);   //Builds the TCPFlags
	uint16 segmentID = segment->segmentID;
	uint32 len = segment->len;
	uint32 normalized_seq_start = ntohl(tp->th_seq) - startSeq();
	uint32 normalized_seq = ntohl(tp->th_seq) + len - startSeq(); // "nice" sequence number
	uint32 normalized_ack_seq = ntohl(tp->th_ack) - peer->startSeq();
	uint32 seq_to_insert = normalized_seq;
	u_char ttl = segment->ttl;
	current_time = segment->current_time; //Set the analyzer time to the current
										  //  packet time

	//If both endpoints of the connection have been observed using the Timestamp
	//  option, then the analyzer should assume that the TS option is being used.
	if (!analyzer->UsesTSOption && usesTimestamps && peer->usesTimestamps)
		analyzer->UsesTSOption = true;

	if (flags.SYN() && !doneSYNACK())
		setState(CONGESTION_3WHS);

	processOptions(tp, flags, normalized_ack_seq);

	//If this packet does not contain an ack sequence number, reuse the previous max
	if (!flags.ACK())
		normalized_ack_seq = getHighestAck();

	segmentCount++;              // incrementPacketCount();
	lastIPID = segmentID;

	//We are observing a packet from a endpoint. If it is considered *dead*, it is not dead now.
	setLife(RSTATE_ENDPOINT_ALIVE);

	// TTLs from the initial SYN are unreliable; ignore those
	// an endpoint's TTL is the TTL of packets from the endpoint, when they arrive at the measurement point
	if (!(flags.SYN() && !flags.ACK()))
		setTTL(ttl);

	//Ensuring that FIN or SYN packets are not used
	if (flags.ACK())
		processACK(normalized_ack_seq, len, flags, tp);

	// the sequence number we want ACKed is different for FINs and SYNs
	if (flags.FIN() || flags.SYN())
		seq_to_insert++;

	// if the packet contained data or was a syn or fin, we're expecting an ACK
	// TODO: This needs to have the check for the gratuitous ack
	if (len > 0 || flags.SYN() || flags.FIN()) {

		// deletion of seq_range happens in TCPState_Endpoint::InsertSequenceNumber, if needed
		SequenceRange *seq_range = new SequenceRange;
		seq_range->min = normalized_seq_start;
		seq_range->to_ack = normalized_seq;
		seq_range->to_ack = seq_to_insert;
		TCPRS_DEBUG_MSG(PEDANTIC, CAT_MISC, "New data segment - seq=%u len=%u timestamp=%f", seq_range->min, len, current_time);
		// this is the value we're building to insert
		Segment *value = new Segment(current_time, len, segmentID);

		// set new packet as SYN or FIN, if appropriate
		if (flags.FIN()) {
			value->setFIN();
			setState(CONGESTION_CONN_CLOSE);
		}
		if (flags.SYN())
			value->setSYN();
		if (flags.RST())
			value->setRST();

		//This adds the sequence number to the range for inflight data
		insertSequenceNumber(seq_range, value, sendTimestampVal,
				normalized_ack_seq);

		setHighestSeq(seq_to_insert);
	}

	if (!flags.FIN() && !flags.SYN())
		processOutstandingData(normalized_ack_seq);

	updatePrevWindow();
	updateLastSeqSent(seq_to_insert);
	addTimeStamp(sendTimestampVal);
	setHighestAck(normalized_ack_seq);
}

//Valgrind Safe
SequenceRange* TCPRS_Endpoint::getAckRange(bro_uint_t sequence) {
	SequenceRange* seq_range;
	loop_over_list(outstandingData, l) {
		seq_range = outstandingData[l];
		if (seq_range->min == sequence)
			return seq_range;
	}
	return NULL;
}

//If any of the outstanding data ranges fall under one of the three paired
//  conditions, then seq spans some part of a previous unacknowledged seq of data
// The three cases are as follow:
//  1. The sequence is completely encapsulated by or is a specific range
//      Ex. Seq = 1000 1100 1100(min max to_ack) outstanding_data[l] = 1000 1100 1100 OR
//                                               outstanding_data[l] = 1025 1075 1075
//  2. The sequence contains the beginning of some range
//      Ex. Seq = 1000 1100 1100(min max to_ack) outstanding_data[l] =  900 1050 1050
//  3. The sequence contains the end of some range
//      Ex. Seq = 1000 1100 1100(min max to_ack) outstanding_data[l] = 1050 1200 1200
//  4. The sequence is contained in the range
//      Ex. Seq = 1000 1100 1100(min max to_ack) outstanding_data[l] =  900 1200 1200
//
//Valgrind Safe

/* This contains an extraneous condition, case 4. Only three cases are necessary to detect this */
bool TCPRS_Endpoint::spansPreviousTX(SequenceRange* seq) {
	loop_over_list(outstandingData, l) {
		if ((outstandingData[l]->min >= seq->min
				&& outstandingData[l]->to_ack <= seq->to_ack) ||    //Case 1
				(outstandingData[l]->to_ack > seq->min
						&& outstandingData[l]->to_ack <= seq->to_ack) || //Case 2
				(outstandingData[l]->min >= seq->min
						&& outstandingData[l]->min < seq->to_ack) ||   //Case 3
				(outstandingData[l]->min <= seq->min
						&& outstandingData[l]->to_ack >= seq->to_ack))  //Case 4
				{
			return true;
		}
	}
	return false;
}

//Valgrind Safe
DuplicateAck* TCPRS_Endpoint::removeDuplicateAck(uint32 seq) {
	HashKey *h = new HashKey(seq);

	// Remove will delete the key
	DuplicateAck *result = (DuplicateAck *) duplicateAcknowledgments.Remove(h);

	delete h;

	return result;
}

//Valgrind Safe
//  actual remove function for dict (gets its own function because
//    we have to make a hashkey out of a sequence number)
Segment* TCPRS_Endpoint::removeSequenceNumber(uint32 seq) {
	HashKey *h = new HashKey(seq);

	// Remove will delete the key
	Segment *result = (Segment *) expectedAcks.Remove(h);

	delete h;

	return result;
}
//Valgrind Safe
void TCPRS_Endpoint::rebuildRange(SequenceRange* range) {
	SequenceRange* seq = NULL;
	Segment* packet = NULL;
	PList(SequenceRange) holding;

	for (int i = outstandingData.length() - 1; i >= 0; i--) {
		seq = outstandingData[i];
		//If the sequence to ack is less than or equal to the range to ack...
		if (seq && Sequence_number_comparison(seq->to_ack, range->to_ack) < 1) {
			seq = outstandingData.remove(seq);
			//If the range consists of part of this range, then we need to
			//  reconstruct this.
			if (seq->min >= range->min) {
				packet = removeSequenceNumber(seq->to_ack);

				if (packet) {
					delete packet;
					packet = NULL;
				}

				delete seq;
				seq = NULL;

			}

			//If a sequence exists, then range does not cover the entire seq_range
			//  Return this to the list
			if (seq) {
				//if (!outstandingData.is_member(seq, Reverse_sequence_range_comparison)) { // want a set, not a list
				if (!outstandingData.is_member(seq)) { // want a set, not a list
					holding.insert(seq);
				} else {
					delete seq;
					seq = NULL;
				}
			}

		} else {
			//The sequence to ack is greater than the range to ack
			break;
		}
	}

	while (holding.length() > 0) {
		//Reinsert the elements that were taken out while iterating the list.
		outstandingData.sortedinsert(holding.get(),
				Reverse_sequence_range_comparison);
	}

	//Range covers the lower portion of this sequence, we need to resize and reinsert
	if (seq && (seq->min < range->to_ack))
		seq->min = range->to_ack;
}

/* *****************************************************************************
 * Start of development code
 *
 *
 *
 * ****************************************************************************/

//Valgrind Safe
void TCPRS_Endpoint::insertDupAck(uint32 sequence) {
	HashKey *h = new HashKey(sequence);

	DuplicateAck *val = (DuplicateAck *) duplicateAcknowledgments.Lookup(h);

	//If this value exists, it is an existing duplicate acknowledgment
	if (val) {
		val->updateDupAck(current_time); // Update time of the dup ack to most recent
	} else {
		val = new DuplicateAck(sequence, current_time);
		duplicateAcknowledgments.Insert(h, val);
	}

	throwDuplicateAckEvent(sequence, val->getDupCount());

	delete h;
}

//Hmm ... seq_to_ack is the right actual value... note this for correcting later
// first "real" method.  inserts sequence number -> packet mapping into our dictionary
//Valgrind Safe
void TCPRS_Endpoint::insertSequenceNumber(SequenceRange *sequence,
		Segment *segment, uint32 ts, uint32 normalized_ack_seq) {
	ASSERT(segment); ASSERT(sequence);

	HashKey *h = new HashKey(sequence->to_ack);
	HashKey *key = new HashKey(sequence->min);
	bool overlapsPreviouslyObservedSegment = false;
	Segment *previouslyObservedSegment = NULL;

	//This is the possibility that the packet never made it to the observation
	//  point and that we will not have a packet for it. This does not mean that
	//  it has been acknowledged either.
	// the previous value for this sequence number, if any

	if (sequenceWrapLtEq(sequence->to_ack, getHighestSeq())) {
		previouslyObservedSegment = (Segment *) expectedAcks.Lookup(h);

		//Does this transmission span a previously transmitted segment?
		//This is not entirely true in cases where the sequence space has wrapped
		// around and the sequence to ack is smaller than the highest ack but in all
		// actuality, seq to ack is a new packet and not an older packet.
		if (!previouslyObservedSegment)
			overlapsPreviouslyObservedSegment = spansPreviousTX(sequence);
	}

	//If a packet exists with this sequence number, this is a retransmit
	// else
	//This sequence is a retransmission that never made it to the observation
	//  point. This has awkward effects on the current algorithm as it does
	//  not have record of the packet and does not realize that this is
	//  part of outstanding data

	if (previouslyObservedSegment) {
		//The analyzer has seen this packet before and has not received an acknowledgement
		//  for the packet yet.
		//printf("\tPrev_value Rexmit %i, at %f\n", seq->min, current_time);

		//If this is a hardware dup, clean up and dont process.
		if (segment->isHWDup(previouslyObservedSegment->getID())) {
			delete segment;
			delete h;
			delete key;
			delete sequence;
			return;
		}

		processRetransmissionEvent(previouslyObservedSegment, key, sequence, ts,
				REXMIT_PREV_OBSERVED);

		if (segment)
			delete segment;

	} else if (overlapsPreviouslyObservedSegment) {
		//This packet spans a previously transmitted segment, a property of a
		//  retransmitted packet

		processRetransmissionEvent(segment, key, sequence, ts,
				REXMIT_SPANS_PREVIOUS);

		//This packet does not exist yet as this is the first time we have seen it.
		expectedAcks.Insert(h, segment);

	} else if (sequenceWrapLtEq(sequence->to_ack, peer->getHighestAck())) {
		//This is a retransmission of a previously acknowledged packet. The
		//  ack may have been delayed or lost. The heuristic should make up
		//  somewhere.

		//printf("\tPrev_Ackd Rexmit %i, at %f\n", seq->min, current_time);
		//TODO: Differentiate between spurious and non-spurious retransmissions
		processRetransmissionEvent(segment, key, sequence, ts,
				REXMIT_PREV_ACKNOWLEDGED);

		//We may still need to observe this packet for the purposes for spurious
		//  rto detection
		expectedAcks.Insert(h, segment);

		//This has been acknowledged already so lets dispose of the entry
		//if( value )
		//    delete value;

	} else if (sequenceWrapLt(sequence->min, peer->getHighestAck())) {
		//If part of this segment has already been acknowledged, this is a
		//  retransmission

		processRetransmissionEvent(segment, key, sequence, ts,
				REXMIT_PARTIALLY_ACKED);
		expectedAcks.Insert(h, segment);

	} else {

		//If the sequence to acknowledge with this packet is less than the highest
		//  observed sequence number sent from this endpoint, then this is out of
		//  order and possibly a retransmission
		if (sequenceWrapLt(sequence->to_ack, getHighestSeq())) {
			segment->setOrdering(ORDERING_UNKNOWN);

			//If timestamps are enabled, lets look at the timestamps to verify
			//  if the packet is out of order or a retransmission
			sequenceTimestampCheck(sequence, segment, ts, key);

			//Lets see if we can determine if this is a rtx or reordered by the ack
			sequenceAckCheck(sequence, segment, key, normalized_ack_seq);

			//If the packet has timestamps enabled, and the granularity of the
			//  timestamps was too coarse, attempt to look at the gap to
			//  make a decision about the packet.
			sequenceGapCheck(sequence, segment, ts, key);

			//If the packet could not be defined as an out-of-order packet or a
			//  retransmission, then this will be declared as an ambiguous
			//  out-of-order transmission
			if (segment->getOrdering() == ORDERING_UNKNOWN)
				processAmbigousReordering(segment, sequence);

		} else {
			//If the packet is not considered to be out-of-order, then process the
			//  packet normally.
			if (sequenceWrapLt(getHighestSeq(), sequence->min)) {
				//This packet has a sequence floor that does not match the previous ceiling
				//  of the data sequence range sent by the endpoint. This means that a
				//  a gap exists in the sequence space between this packet and the packet
				//  that was supposed to arrive before this one.
				updateSequenceGap(sequence->min);
			}
			lastSegmentRetransmitted = false;

		}
		expectedAcks.Insert(h, segment);
	}

	//Increment the gap segment difference for the purpose of examining how 'out
	//  of order' a segment actually is.
	endpointGapInfo.segment_difference++;

	if (segment && !(segment->getOrdering() == ORDERING_RETRANSMISSION)) {
		//Implies that this is new data.
		if (getRecoveryState() == RECOVERY_EARLY_RTX
				|| getRecoveryState() == RECOVERY_FAST_RTX
				|| getRecoveryState() == RECOVERY_FACK) {
			//Implies that the current segment is new data being sent within a recovery
			//  window
			throwFastRecoveryTransmitEvent(sequence->min);
			//Need to throw an event for segments sent with condition 5 from RFC 5681.
		} else if (getRecoveryState() == RECOVERY_NORMAL) {
			//Implies that this is new data sent during normal operation
			DuplicateAck* dup = findDupAck(sequence, key, segment);

			if (dup && (dup->getDupCount() < ACK_COUNT)) {
				//Need to check to see if this was in response to a duplicate acknowledgement
				//  outside of a recovery window. If so, this is likely to be a limited transmit
				//  generated segment
				double min_dist = peer->rttvar;
				if (min_dist < 0.001)
					min_dist = 0.001;

				double lower_bound = (current_time - peer->rtt) - min_dist;
				double upper_bound = (current_time - peer->rtt) + min_dist;

				if ((lower_bound <= dup->getFirst()
						&& dup->getFirst() <= upper_bound)) {
					//This is the response to the first duplicate acknowledgement
					throwLimitedTransmitEvent(sequence->min);
				} else if ((dup->getDupCount() > 1)
						&& (lower_bound <= dup->getTS(DOUBLE))
						&& (dup->getTS(DOUBLE) <= upper_bound)) {
					//This is the response to the second duplicate acknowledgement
					throwLimitedTransmitEvent(sequence->min);
				}
			}
			// else
			//Couldn't find a duplicate acknowledgement to test.
			//  -- or --
			//The amount of duplicate acknowledgements outstanding have erased
			//  the first two values.
		}
	}

	// If this is the first time we've seen this segment, and it isn't out of
	// order, then lets remember that for tracking duplicate acknowledgment data
	if (!previouslyObservedSegment && segment->getOrdering() == ORDERING_NORMAL)
		segment->original_observed = true;

	if (getRecoveryState() == RECOVERY_NORMAL)
		segment->sentDuringLossRecovery = true;

	//Setlike list
	if (sequenceWrapLtEq(highestSequence, sequence->min)
			|| !isMemberOutstanding(sequence))
		outstandingData.sortedinsert(sequence,
				Reverse_sequence_range_comparison);
	else
		delete sequence;

	delete key;
	delete h;

	//need to skew the time a little for this case same as above...
	//! Important
	if (!rtoTimer.running())
		rtoTimer.updateRTOTimer(current_time, estimatedRTO);
}

//The list should always been in reverse sorted order, such that the list is
//  organized with the highest sequence numbers at the front, and the lowest at
//  the end. Thus, if the current sequence minimum is greater than the current
//  segment in the list's to_ack and the sequence hasn't been already found, it
//  must not be in the list, allowing us to short circuit the traversal of the
//  list and hopefully save a few operations.
bool TCPRS_Endpoint::isMemberOutstanding(SequenceRange* seq) {
	loop_over_list(outstandingData, i) {
		if (sequenceWrapLtEq(outstandingData[i]->to_ack, seq->min))
			return false;
		if (memcmp(outstandingData[i], seq, sizeof(SequenceRange)) == 0)
			return true;
	}
	return false;
}

void TCPRS_Endpoint::processOutOfOrderEvent(Segment* segment) {

	//Increment the number of out of order packets observed going to
	//  the other endpoint.
	peer->recordOutOfOrder();

	//Set this packet as an out of order segment
	segment->setOrdering(ORDERING_REORDERED);

	lastSegmentRetransmitted = false;
}

void TCPRS_Endpoint::processRetransmissionEvent(Segment* packet,
		HashKey* key, SequenceRange* seq, uint32 ts,
		RETRANSMISSION_REASON_CODE reason) {
	RETRANSMISSION_TYPE_CODE rtype;
	double confidence = 0.0;
	double estimated_net_time = current_time;
	if (!IS_UNDEFINED(peer->rtt))
		estimated_net_time += (0.5 * (peer->rtt - peer->rttvar));

	packet->updateTimestamp(current_time);          //Add this timestamp to the

	//Lets make the assumption that the connection may be dead and observe
	peer->setLife(RSTATE_ENDPOINT_DEAD);

	// set our new value as a rtx
	//packet->setRTX();
	packet->incrementRTX();
	packet->setOrdering(ORDERING_RETRANSMISSION);

	//Update the last observed time of a retransmission
	deltaOutstandingData.rtx_timestamp = current_time;

	// record this rtx and throw the event
	recordRetransmission(packet->getPacketSize());

	//Add the retransmission to this endpoint's list of retransmissions. This
	//  will be used to later determine if the retransmission was unnecessary
	addRetransmission(seq, packet);

	//If this retransmission falls within a block that is being retransmitted as
	//  part of a fast retransmission.
	/*if( seq->min > peer->getHighestAck() ) {
	 throwRetransmissionEvent(seq->min, reason, RTYPE_REXMIT, NECESSARY);
	 return;
	 }*/

	TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "recovery window=%i recovery_is_normal=%i seq_to_ack=%i",
			recoverySequence,getRecoveryState() == RECOVERY_NORMAL,  seq->to_ack);

	if (getRecoveryState() != RECOVERY_NORMAL
			&& seq->to_ack <= recoverySequence) {
		//printf("%i is the sequence\n", seq->min);
		//printf("%f is the elapsed time\n", rtoTimer.elapsedTime(current_time));
		//printf("%f is the rto\n", rtoTimer.RTO());
		//printf("%i is the result of isRTO\n", isRTO(seq, packet, reason, key));
		//double probableRTO = getLikelyMaxRTO(previousRTO, rtoTimer.elapsedTime(current_time));
		//printf("%f is the probable rto\n", probableRTO);
		//printf("%f is the previous RTO\n", previousRTO);

		if (packet->RTXCount() > 1) {
			//printf("This sequence has been retransmitted more than once\n");
			//printf("%f is the elapsed time\n", rtoTimer.elapsedTime(current_time));
			//printf("%f is the rto\n", rtoTimer.RTO());

			if (rtoTimer.expired(current_time) || packet->isSYN())          //||
					//(!isResponse(current_time)) )
					{
				//printf("%i sequence has expired on the rto timer\n", seq->min);
				processRTO(packet, seq, reason, RTYPE_BRUTE_FORCE_RTO,
						NECESSARY);
				lastRetransmissionRTO = true;
			} else if (lastRetransmissionSeq == seq->min
					&& lastRetransmissionRTO) {
				processRTO(packet, seq, reason, RTYPE_BRUTE_FORCE_RTO,
						NECESSARY);
				lastRetransmissionRTO = true;
			} else {
				TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);
				//printf("%i sequence has not expired on the rto timer\n", seq->min);
				throwRetransmissionEvent(packet, seq->min, reason, RTYPE_REXMIT,
						NECESSARY);
				lastRetransmissionRTO = false;
			}
		} else {
			DuplicateAck* dup = findDupAck(seq, key, packet);
			bool rto_expired = rtoTimer.expired(current_time);

			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "rto=%f elapsed=%f dup=%p", rtoTimer.RTO(), rtoTimer.elapsedTime(current_time), dup);
			//If this is an RTO and this is not in response to some duplicate ack...
			if (rto_expired && !dup) {
				processRTO(packet, seq, reason, RTYPE_RTO, NECESSARY);
				lastRetransmissionRTO = true;
			} else if (lastRetransmissionSeq == seq->min
					&& lastRetransmissionRTO) {
				processRTO(packet, seq, reason, RTYPE_BRUTE_FORCE_RTO,
						NECESSARY);
				lastRetransmissionRTO = true;
			} else if (rto_expired) {
				SCORE* result = scoreRetransmission(seq, packet, reason, key);

				TCPRS_DEBUG_MSG(LVL_1, CAT_RETRANSMIT, "RTO classification - seq=%u rtype=%u confidence=%f", seq->min, result->type, result->confidence);
				if ((result->type == RTYPE_RTO || result->type == RTYPE_RTO_NO_DUPACK) &&
						result->confidence > 0.68) {
					processRTO(packet, seq, reason, RTYPE_RTO, confidence);
				} else {
					throwRetransmissionEvent(packet, seq->min, reason, RTYPE_REXMIT,
							NECESSARY);
					lastRetransmissionRTO = false;
				}
				delete result;

			} else {
				TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);
				throwRetransmissionEvent(packet, seq->min, reason, RTYPE_REXMIT,
						NECESSARY);
				lastRetransmissionRTO = false;
			}
		}
		lastRetransmissionSeq = seq->min;
		lastRetransmissionTS = current_time;
		lastSegmentRetransmitted = true;
		return;
	}


	if (getRecoveryState() == RECOVERY_NORMAL &&
			lastSegmentRetransmitted) {
		/* assume this is the continuation of loss recovery where
		 * the analyzer did not have a correct approximation of the loss
		 * recovery window */
		if (seq->min == lastRetransmissionSeq && lastRetransmissionRTO) {
			/* if the last retransmisison was a retransmission timeout of the
			 * same segment, this is likely another RTO
			 */
			processRTO(packet, seq, reason, RTYPE_BRUTE_FORCE_RTO,
									NECESSARY);
			lastRetransmissionRTO = true;
		} else {
			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);

			throwRetransmissionEvent(packet, seq->min, reason, RTYPE_REXMIT,
									NECESSARY);
			lastRetransmissionRTO = false;
			setRecoveryState(RECOVERY_UNKNOWN);
		}
		lastRetransmissionSeq = seq->min;
		lastRetransmissionTS = current_time;
		return;
	} else if (getRecoveryState() != RECOVERY_NORMAL) {
		/* we assume that if we are still recovering from a previous loss and
		 * it wasn't caught by previously detailed heuristics that this must be
		 * retransmission via loss recovery
		 */

		TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);

		throwRetransmissionEvent(packet, seq->min, reason, RTYPE_REXMIT,
				NECESSARY);
		lastRetransmissionRTO = false;
		return;
	} else {
		TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "normal_recovery=%i last_segment_retransmitted=%i", (getRecoveryState() == RECOVERY_NORMAL), lastSegmentRetransmitted);
		lastRetransmissionRTO = false;
		SCORE* result = scoreRetransmission(seq, packet, reason, key);

		if (!result)
			return;

		if (result->confidence < LOW_CONFIDENCE_THRESH) {
			rtype = RTYPE_UNKNOWN;
			confidence = 1.0 - result->confidence;
			TCPRS_DEBUG_MSG(LVL_1,CAT_RETRANSMIT, "retransmission flagged as unknown due to low confidence - conf=%f", result->confidence);
		} else {
			rtype = result->type;
			confidence = result->confidence;
		}
		delete result;
	}


	TCPRS_DEBUG_MSG(LVL_1, CAT_RECOVERY, "recovery sequence set by sequence=%i to seq=%i", seq->min, highestSequence);
	recoverySequence = highestSequence;

	switch (rtype) {
	case RTYPE_RTO:
	case RTYPE_RTO_NO_DUPACK:
		processRTO(packet, seq, reason, rtype, confidence);
		lastRetransmissionRTO = true;
		break;

	case RTYPE_FAST_TRIPDUP:
	case RTYPE_FAST_SPECULATIVE:
	case RTYPE_SEG_EARLY_REXMIT:
	case RTYPE_BYTE_EARLY_REXMIT:
	case RTYPE_SACK_SEG_EARLY_REXMIT:
	case RTYPE_SACK_BYTE_EARLY_REXMIT:
	case RTYPE_SACK_BASED_RECOVERY:
		processFastRetransmission(packet, seq, reason, rtype, confidence);
		break;

	case RTYPE_FACK_BASED:
		throwRetransmissionEvent(packet, seq->min, reason, rtype, confidence);
		if (getRecoveryState() == RECOVERY_NORMAL)
			setRecoveryState(RECOVERY_FACK);
		break;

	case RTYPE_TESTING:
	case RTYPE_NO_RTT:
	case RTYPE_NO_TS:

		throwRetransmissionEvent(packet, seq->min, reason, rtype, confidence);

		if (getRecoveryState() == RECOVERY_NORMAL)
			setRecoveryState(RECOVERY_RTO);

		break;
	case RTYPE_UNKNOWN:
		throwRetransmissionEvent(packet, seq->min, reason, rtype, confidence);

		if (getRecoveryState() == RECOVERY_NORMAL)
			setRecoveryState(RECOVERY_UNKNOWN);

		break;

	default:
		break;
	}

	lastRetransmissionSeq = seq->min;
	lastRetransmissionTS = current_time;
	lastSegmentRetransmitted = true;

	//Add this rexmit to the list for spurious rexmit checking later on
	/*SEGMENT* ptr = new SEGMENT;
	 if( ptr != NULL ) {
	 ptr->min = seq->min;//min_bound;
	 ptr->to_ack = seq->to_ack;
	 ptr->timestamp = current_time;
	 ptr->rtt2 = peer->rtt;        //What is the estimated timeframe to see the ack?
	 ptr->rttvar = peer->rttvar;   //What is the variance in this measurement?
	 ptr->necessary = false;
	 ptr->confidence = UNDEFINED;
	 ptr->original = ((current_time == packet->getPacketSentTimestamp()) ?
	 UNDEFINED : packet->getPacketSentTimestamp());
	 addRexmitToList(ptr);
	 }*/
}

void TCPRS_Endpoint::addRetransmission(SequenceRange* seq, Segment* packet) {
	//Does this packet exist in the list? If so , add it to the list with the
	//  new timestamp
	/*loop_over_list(rexmits, i) {
	 if( rexmits[i]->min == seq->min ) {
	 SEGMENT* ptr = new SEGMENT;
	 if( ptr != NULL ) {
	 ptr->min = seq->min;
	 ptr->to_ack = seq->to_ack;
	 ptr->timestamp = current_time;
	 ptr->rtt2 = peer->rtt;
	 ptr->rttvar = peer->rttvar;
	 ptr->necessary = false;
	 ptr->confidence = UNDEFINED;
	 //If this is the first time this has been seen, leave it undefined
	 ptr->original = ((current_time == packet->getPacketSentTimestamp()) ?
	 UNDEFINED : packet->getPacketSentTimestamp());
	 addRexmitToList(ptr);
	 }
	 return;
	 }
	 }*/
}

SCORE* TCPRS_Endpoint::scoreRetransmission(SequenceRange* seq,
		Segment* packet, RETRANSMISSION_REASON_CODE reason, HashKey* key) {

	Segment* parent = packet;
	double target = UNDEFINED;
	double lower_bound = UNDEFINED;
	double upper_bound = UNDEFINED;
	DuplicateAck* dup = NULL;
	bro_int_t owin = getHighestSeq() - peer->getHighestAck();
	SCORE* result = new SCORE;
	float scores[RTYPE_COUNT];
	memset(scores, 0x0, sizeof(float) * RTYPE_COUNT);

	bool has_fack_timestamps = (fackCount > 0);
	bool has_rtt_sample = !IS_UNDEFINED(peer->rtt);

	double estimated_net_time = current_time;
	if (!IS_UNDEFINED(peer->rtt))
		estimated_net_time += (0.5 * (peer->rtt - peer->rttvar));

	double min_dist = peer->rtt;

	if (has_rtt_sample) {
		//If the rtt is far too small, variance may not cover such things such as
		//  occasional delay due to congestion on the network between the observation
		//  point and the endpoint. Thus , it is necessary to increase the
		//  the denominator of the confidence_value by some function of the rtt
		//  f(x) = rtt * ( 1 - 2log(1000*rtt))
		if (min_dist < 0.001)
			min_dist = peer->rtt * (1.0 - (2.0 * log10(1000.0 * peer->rtt)));
		target = current_time - peer->rtt;
		lower_bound = target - min_dist;
		upper_bound = target + min_dist;
	}

	result->confidence = 0.0;
	result->type = RTYPE_UNKNOWN;

	TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"CONTEXT: network_time=%f seq=%u rtt=%f rttvar=%f", current_time, seq->min, min_dist, peer->rttvar);

	if (packet->isSYN() || packet->isFIN()) {
		result->confidence = 1.0;
		result->type = RTYPE_RTO;
		TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "RTO(SYN/FIN)", result->confidence);
		return result;     //No need to check the other heuristics
	}

	//We should attempt to locate the original packet to find the elapsed time
	//  since the packet was transmitted.
	if (reason != REXMIT_PREV_OBSERVED) {
		parent = findLikelyOriginalsSegment(seq);
		if (!parent)
			parent = packet;
	}

	dup = findDupAck(seq, key, packet);
	if (parent && dup) {
		//if the original segment was observed and the duplicate acknowledgment
		//  was observed before that timestamp, don't use the duplicate acknowledgment
		if (parent->original_observed && dup->getLast() < parent->getPacketSentTimestamp()) {
			TCPRS_DEBUG_MSG(LVL_3, CAT_RETRANSMIT, "none of the timestamps associated with "
					"the duplicate acknowledgment found occur after the original packet: "
					"last=%f original_packet=%f", dup->getLast(), parent->getPacketSentTimestamp());
			dup = NULL;
		}
	}

	//Forward Acknowledgement based recovery detection
	if (has_fack_timestamps && has_rtt_sample) {
		double confidence_value = UNDEFINED;
		double best_match = UNDEFINED;
		double match_value = UNDEFINED;
		double modifier = UNDEFINED;
		int count = 0;

		double tmp = UNDEFINED;

		for (unsigned int i = 0; i < ((fackCount > ACK_COUNT) ? ACK_COUNT : fackCount);
				i++) {
			//If Forward Acknowledgments have not been observed
			//TODO: This line seems strange.
			if (!fackTimestamps[i])
				continue;

			/*If the packet was originally sent as the same time as the retransmission,
			 * it is fair to make the assumption that either the original packet was
			 * never observed, or dropped by the analyzer to maintain minimal state
			 * information
			 *
			 * If the analyzer has observed the original packet then discount any
			 * forward acknowledgment trigger that occurs before the original packet.
			 */
			if (!DBL_EQUIV(parent->getPacketSentTimestamp(),packet->getLatestTimestamp()) &&
					*fackTimestamps[i] < parent->getPacketSentTimestamp())
				continue;

			tmp = (target - *fackTimestamps[i]) * (target - *fackTimestamps[i]);

			if (*fackTimestamps[i] >= parent->getPacketSentTimestamp()) {
				count++;
			}

			if (IS_UNDEFINED(best_match) || match_value > tmp) {
				best_match = *fackTimestamps[i];
				match_value = tmp;

				if (*fackTimestamps[i] >= parent->getPacketSentTimestamp()) {
					//Since each retransmission is in response
					//  to an event, it becomes less likely to be
					//  this event as we observe more triggers
					modifier = 1.0 / ((double) count);
				}
			}
		}

		if (!IS_UNDEFINED(best_match)) {
			float proximity = (fabs(target - best_match) / min_dist);
			confidence_value = 1.0 / (1.0 + proximity);

			TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT, "network_time=%f seq=%u type=%s proximity=%f target=%f best_match=%f min_dist=%f modifier=%f", current_time, seq->min, "FACK_BASED", proximity, target, best_match, min_dist, modifier);
			TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT, "network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "FACK_BASED", confidence_value);
			if (!IS_UNDEFINED(modifier)) {
				confidence_value *= modifier;
			}

			if (confidence_value > result->confidence) {
				result->confidence = confidence_value;
				result->type = RTYPE_FACK_BASED;
			}
		}
	}

	//Fast Retransmission based recovery detection
	if (dup) {
		if (has_rtt_sample) {
			//Triple duplicate acknowledgement trigger
			if (dup->getDupCount() >= 3) {
				double confidence_value = UNDEFINED;
				double proximity = UNDEFINED;

				proximity = fabs(target - dup->getTS(TRIPLE))/ min_dist;
				confidence_value = 1.0 / (1.0 + proximity);

				TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "SACK/FAST3", confidence_value);
				if ((confidence_value > result->confidence)
						|| DBL_EQUIV(result->confidence, confidence_value)) {

					result->confidence = confidence_value;
					result->type = ((analyzer->sack_in_use) ?
									RTYPE_SACK_BASED_RECOVERY :
									RTYPE_FAST_TRIPDUP);
				}
			}

			// NOTE: This heuristic is fine for sender side analysis but does
			//            not hold well for receiver side analysis
			//


			//Early Retransmit Byte based recovery trigger
			if (getMSS() > 0) {

				uint32 ER_thresh =
						(int) (ceil(owin / ((double) getMSS())) - 1.0);

				if (ER_thresh <= 0)
					ER_thresh = 1;

				if (owin < (4 * getMSS()) && dup->getDupCount() >= ER_thresh) {
					double confidence_value = UNDEFINED;
					double proximity = UNDEFINED;

					uint32 arrayIndex = ER_thresh - 1;

					if (dup->getTS(arrayIndex) <= upper_bound
							&& dup->getTS(arrayIndex) >= lower_bound) {
						confidence_value = 1.0;
					} else {
						proximity = fabs(target - dup->getTS(arrayIndex))
								/ min_dist;
						confidence_value = 1.0 / (1.0 + proximity);
					}

					TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f",
							current_time, seq->min, "BYTE_EARLY/SACK_BYE_EARLY", confidence_value, proximity);
					if ((confidence_value > result->confidence)
							|| DBL_EQUIV(result->confidence, confidence_value)) {

						if (!analyzer->sack_in_use) {
							dup->setFastRTX();
							result->confidence = confidence_value;
							result->type = RTYPE_BYTE_EARLY_REXMIT;
							TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "BYTE_EARLY", result->confidence);
						} else if (analyzer->sack_in_use
								&& ((uint32) (owin - getMSS()) == sackedBytes)) {
							dup->setFastRTX();
							result->confidence = confidence_value;
							result->type = RTYPE_SACK_BYTE_EARLY_REXMIT;
							TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "SACK_BYTE_EARLY", result->confidence);
						}
					}

				}
			}

			//Early Retransmit Segment based recovery.
			if (outstandingData.length() < 4) {
				bro_uint_t ER_thresh = outstandingData.length() - 1;
				if (ER_thresh <= 0)
					ER_thresh = 1;

				if (dup->getDupCount() >= ER_thresh) {
					double confidence_value = UNDEFINED;
					double proximity = UNDEFINED;
					uint32 arrayIndex = ER_thresh - 1;
					if (dup->getTS(arrayIndex) <= upper_bound
							&& dup->getTS(arrayIndex) >= lower_bound) {
						confidence_value = 1.0;
					} else {
						proximity = fabs(target - dup->getTS(arrayIndex))
								/ min_dist;
						confidence_value = 1.0 / (1.0 + proximity);
					}

					TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f",
							current_time, seq->min, "SEG_EARLY/SACK_SEG_EARLY", confidence_value, proximity);

					if ((confidence_value > result->confidence)
							|| DBL_EQUIV(result->confidence, confidence_value)) {
						if (!analyzer->sack_in_use) {
							dup->setFastRTX();
							result->confidence = confidence_value;
							result->type = RTYPE_SEG_EARLY_REXMIT;
							TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "SEG_EARLY", result->confidence);
						} else if (analyzer->sack_in_use
								&& ((owin - 1) == sackedSegments)) {
							dup->setFastRTX();
							result->confidence = confidence_value;
							result->type = RTYPE_SACK_SEG_EARLY_REXMIT;
							TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "SACK_SEG_EARLY", result->confidence);
						}
					}
				}
			}

			//Speculative Fast Retransmit trigger detection. Mainly occurs in
			//  the case for which we see a loss in the acknowledgment that would
			//  normally trigger Fast Retransmit based recovery. An older
			//  acknowledgement would normally be responsible since the original
			//  trigger would have been lost.
			if (dup->getDupCount() >= 3) {

				double confidence_value = UNDEFINED;
				double proximity = UNDEFINED;
				uint32 i_to_end = (
						(dup->getDupCount() >= ACK_COUNT) ?
								ACK_COUNT : dup->getDupCount());
				for (unsigned int i = 0; i < i_to_end; i++) {
					proximity = fabs(target - dup->getTS(i)) / min_dist;    //Ratio
					confidence_value = 1.0 / (1.0 + proximity);
					confidence_value *= 1.0 / (abs(i - TRIPLE) + 1.0); //ack distancing

					TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f",
							current_time, seq->min, "SACK/FAST-SPEC", confidence_value, proximity);

					if (DBL_EQUIV(confidence_value, result->confidence) &&
							(result->type == RTYPE_SACK_BASED_RECOVERY ||
							 result->type == RTYPE_FAST_TRIPDUP)) {
						//Ignore and continue on
					} else if (confidence_value > result->confidence) {
						dup->setFastRTX();
						result->confidence = confidence_value;
						result->type = (
								(analyzer->sack_in_use) ?
										RTYPE_SACK_BASED_RECOVERY :
										RTYPE_FAST_SPECULATIVE);
						TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f", current_time, seq->min, "SACK/FAST-SPEC", result->confidence);
					}
				}
			}
		}
	}

	TCPRS_DEBUG_MSG(LVL_7, CAT_RETRANSMIT, "dup=%p result=%i UNKNOWN=%i", dup, result->type, RTYPE_UNKNOWN);
	if (!dup && (result->type == RTYPE_UNKNOWN ||
			DBL_EQUIV(result->confidence,0.0) || IS_UNDEFINED(result->confidence))) {
		result->confidence = 1.0;
		result->type = RTYPE_RTO_NO_DUPACK;
		TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"expired=%i elapsed=%f rto_approximation=%f", rtoTimer.expired(estimated_net_time), rtoTimer.elapsedTime(estimated_net_time), rtoTimer.RTO());
		TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "RTO_NO_DUP", result->confidence);
		return result;
	}

	TCPRS_DEBUG_MSG(LVL_7, CAT_RETRANSMIT, "rto.expired=%i result.type=%i elapsed=%f rto=%f",
			rtoTimer.expired(estimated_net_time), result->type, rtoTimer.elapsedTime(estimated_net_time),
			rtoTimer.RTO());
	if (rtoTimer.expired(estimated_net_time) && result->type != RTYPE_UNKNOWN
			/*&& ((rtoTimer.elapsedTime(current_time) - rtoTimer.RTO())
					< rtoTimer.RTO())*/) {
		double proximity = fabs(rtoTimer.elapsedTime(current_time) - rtoTimer.RTO())
				/ rtoTimer.RTO();
		double confidence_value = 1.0 / (1.0 + proximity);
		TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f",
				current_time, seq->min, "RTO(estimated)", confidence_value, proximity);
		if (confidence_value > result->confidence) {
			result->confidence = confidence_value;
			result->type = RTYPE_RTO;
		}
	} else if (rtoTimer.expired(estimated_net_time)
			&& result->type == RTYPE_UNKNOWN) {
		/* in the event that we have a valid estimate, lets look
			at the proximity to the latest duplicate acknowledgement to see
			if this retransmission is in response to a received acknowledgment

			RTOs are highly likely to appear as part of a timer expiration we
			cannot observe via the traffic. Therefore, we can look to see if
			it appears that the retransmission may be in response to a
			duplicate acknowledgement*/

		/* if a duplicate was observed, lets take a conservative estimate to
		 * the round-trip time.
		 */
		if (dup) {
			double proximity = fabs(dup->getLast() - current_time) / (peer->rtt + peer->rttvar);

			double confidence_value = 1.0 / (1.0 + proximity);
			if (confidence_value < 0.16) {
				confidence_value = 1.0 - (confidence_value / 0.32);
				result->type = RTYPE_RTO;
				result->confidence = confidence_value;
				TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "RTO(expired)", result->confidence);
			} else if (confidence_value > 0.84) {
				confidence_value = ((confidence_value - 0.84) + 0.16) / 0.32;
				result->type = RTYPE_FAST_SPECULATIVE;
				result->confidence = confidence_value;
				TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "FastRTX(unknown)", result->confidence);
			} else {
				/* I model this as everything not within a single standard deviation from a uniform distribution.
				 *
				 * The assumption here may not be valid, but it makes sense from empirical evidence
				 */
				confidence_value = (1.0 - fabs(confidence_value - 0.5)) / (0.5 * STDEV_UNIFORM);
				result->type = RTYPE_TESTING;
				result->confidence = confidence_value;
				TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "unknown(RTO calculation)", result->confidence);
			}
		} else {
			// TODO: this is erroneous when there isn't a duplicate acknowledgment present -- let it fall through to other heuristics in this case
			TCPRS_DEBUG_MSG(LVL_1, CAT_RETRANSMIT, "ERROR: This algorithm doesn't yet account for a lack of duplicate acknowledgement");
		}

	}

	if (DBL_EQUIV(result->confidence,0.0) || IS_UNDEFINED(result->confidence)) {
		TCPRS_DEBUG_MSG(LVL_1, CAT_RETRANSMIT, "could not detect via other methods. seq=%u", seq->min);
		double confidence_value = UNDEFINED;
		double proximity = UNDEFINED;

		TCPRS_DEBUG_MSG(LVL_1, CAT_RETRANSMIT, "path_rtt_estimate=%u no_ts=%u", (!(hasPathRTTEstimate() || IS_UNDEFINED(rtt))),
				(current_time == parent->getPacketSentTimestamp()));
		if (!(hasPathRTTEstimate() || IS_UNDEFINED(rtt))) {

			result->type = RTYPE_NO_RTT;

		} else if (current_time == parent->getPacketSentTimestamp()) {

			result->type = RTYPE_NO_TS;

		} else {
			TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"dup=%.8x dupseq=%u recoverystate=%i highestack=%u",
					dup, ((dup) ? dup->getSeq() : -1), getRecoveryState(), peer->getHighestAck());
			/* Verify whether this is in response to an acknowledgment received or not */
			if (dup && dup->getSeq() == peer->getHighestAck() &&
					getRecoveryState() != RECOVERY_NORMAL) {

				double best_match = UNDEFINED;
				double confidence_value = UNDEFINED;
				double proximity = UNDEFINED;
				uint32 i_to_end = (
						(dup->getDupCount() >= ACK_COUNT) ?
								ACK_COUNT : dup->getDupCount());
				for (unsigned int i = 0; i < i_to_end; i++) {
					proximity = fabs(target - dup->getTS(i)) / min_dist;

					if (IS_UNDEFINED(best_match) || (proximity < best_match && !IS_UNDEFINED(proximity)))
						best_match = proximity;

					TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"DUPACK_MATCHING network_time=%f seq=%u dupacknum=%u proximity=%f",
																					current_time, seq->min, i+1, proximity);

				}

				if (!IS_UNDEFINED(best_match)) {
					proximity = best_match;    //Ratio
					confidence_value = 1.0 / (1.0 + proximity);

					TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f proximity=%f",
																current_time, seq->min, "UNKNOWN(RTO)", confidence_value, proximity);
				}


			}

			if (!((current_time - parent->getPacketSentTimestamp())	>= estimatedRTO)) {

				proximity = (current_time - parent->getPacketSentTimestamp())
						/ estimatedRTO;
				confidence_value = (proximity * proximity);
				result->confidence = confidence_value;
				result->type = RTYPE_TESTING;

				TCPRS_DEBUG_MSG(PEDANTIC,CAT_RETRANSMIT,"network_time=%f seq=%u type=%s score=%f", current_time, seq->min, "testing", result->confidence);

			} else {
				result->type = RTYPE_UNKNOWN;
			}
		}
	}
	return result;

}

bool TCPRS_Endpoint::isRTO(SequenceRange* seq, Segment* packet,
		RETRANSMISSION_REASON_CODE reason, HashKey* key) {
	Segment* parent = packet;
	double target = UNDEFINED;
	double lower_bound = UNDEFINED;
	double upper_bound = UNDEFINED;
	double confidence = UNDEFINED;
	RETRANSMISSION_TYPE_CODE type = RTYPE_UNKNOWN;

	bool has_rtt_sample = !IS_UNDEFINED(peer->rtt);

	double estimated_net_time = current_time;
	if (!IS_UNDEFINED(peer->rtt))
		estimated_net_time += (0.5 * (peer->rtt - peer->rttvar));

	double min_dist = peer->rtt;

	if (has_rtt_sample) {
		//If the rtt is far too small, variance may not cover such things such as
		//  occasional delay due to congestion on the network between the observation
		//  point and the endpoint.
		if (min_dist < 0.001) {
			min_dist = 0.001;
			target = current_time - peer->rtt;
			lower_bound = target - min_dist;
			upper_bound = target + min_dist;
		} else {
			target = current_time - peer->rtt;
			lower_bound = target - peer->rttvar;
			upper_bound = target + peer->rttvar;

		}
	}

	if (packet->isSYN() || packet->isFIN()) {
		confidence = 1.0;
		type = RTYPE_RTO;
	}

	if (rtoTimer.running()) {
		if (rtoTimer.expired(current_time)) {
			confidence = 1.0;
			type = RTYPE_RTO;
		} else {
			if (rtoTimer.elapsedTime(current_time) < 0.0) {
				// Occurs with skewing adjustments. Obviously, this is far too
				//  soon to be a RTO
				TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);
				confidence = 1.0;
				type = RTYPE_REXMIT;
			}

			if (hasPathRTTEstimate()) {
				//RTO will never occur within a round trip time
				if (rtoTimer.elapsedTime(current_time) < getPathRTTEstimate()) {
					confidence = 1.0;
					TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);

					type = RTYPE_REXMIT;
				}

				double proximityScore = 1.0;
				double rttMagnitudeScore = UNDEFINED;
				double rttModifier = 0.25;
				double localProximity;
				FOR_EACH_IN_CLIST(i, peer->ackTimestamps)
				{
					if (!(peer->ackTimestamps[i])
							|| *(peer->ackTimestamps[i]) > current_time)
						continue;

					localProximity = UNDEFINED;

					//For cases such that we are extremely close to the sender, it may be more
					//  prudent to accept cases where the turn around time is much shorter
					//  than we expect.
					if (((current_time - *(peer->ackTimestamps[i])) < min_dist)
							&& (peer->rtt < 0.005)) {
						localProximity = ((current_time
								- *(peer->ackTimestamps[i])) / min_dist);
						if (IS_UNDEFINED(proximityScore)
								|| (localProximity < proximityScore))
							proximityScore = localProximity;
					} else {
						if (lower_bound <= *(peer->ackTimestamps[i])
								&& *(peer->ackTimestamps[i]) <= upper_bound) {
							localProximity = ((current_time
									- *(peer->ackTimestamps[i])) / peer->rtt);
							if (IS_UNDEFINED(proximityScore)
									|| (localProximity < proximityScore))
								proximityScore = localProximity;
						}
					}
				}

				rttMagnitudeScore = getPathRTTEstimate()
						/ rtoTimer.elapsedTime(current_time);
				rttModifier += .5 * (peer->rtt / getPathRTTEstimate());

				double rtoScore = (rttMagnitudeScore * rttModifier)
						+ (proximityScore * (1.0 - rttModifier));

				if (rtoScore < 0.5) {
					if ((1.0 - rtoScore) > confidence) {
						confidence = 1.0 - rtoScore;
						type = RTYPE_REXMIT;
						TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "this message is a rexmit seq=%i", seq->min);

					}
				} else {
					if (rtoScore > confidence) {
						confidence = rtoScore;
						type = RTYPE_RTO;
					}
				}

			}
		}
	}

	//We should attempt to locate the original packet to find the elapsed time
	//  since the packet was transmitted.
	if (reason != REXMIT_PREV_OBSERVED) {

		parent = findLikelyOriginalsSegment(seq);
		if (!parent)
			parent = packet;
	}

	if ((type == RTYPE_RTO) || (type == RTYPE_RTO_NO_DUPACK))
		return true;
	return false;

}

//This likely will only work sender side. I believe that more information should
//  be retained for receiver side analysis because of the proximity to acknowledgements
Segment* TCPRS_Endpoint::findLikelyOriginalsSegment(SequenceRange* seq) {
	Segment* to_return = NULL;

	uint32 overlap = 0;
	uint32 to_find = 0;

	uint32 seq_floor;
	uint32 seq_ceil;
	loop_over_list(outstandingData, l) {
		//If there is no possible overlap, continue
		if (seq->min >= outstandingData[l]->to_ack
				|| seq->to_ack <= outstandingData[l]->min)
			continue;

		seq_floor = (
				(seq->min > outstandingData[l]->min) ?
						seq->min : outstandingData[l]->min);
		seq_ceil = (
				(seq->to_ack < outstandingData[l]->to_ack) ?
						seq->to_ack : outstandingData[l]->to_ack);

		if (seq_ceil - seq_floor > overlap) {
			overlap = seq_ceil - seq_floor;
			to_find = outstandingData[l]->to_ack;
		}
	}

	if (overlap > 0) {
		HashKey *h = new HashKey(to_find);

		to_return = (Segment *) expectedAcks.Lookup(h);

		delete h;
	}

	return to_return;
}

void TCPRS_Endpoint::examinePotentialSpuriousRexmits() {
	//If a minrtt sample does not exist, then it is not possible to use this
	//  method.
	return;

	if (IS_UNDEFINED(minRTT)
			|| rexmits.length() == 0|| IS_UNDEFINED(peer->minRTT))
		return;

	//double cutoff;
	SEGMENT* seg;
	PList(SEGMENT) current_rexmits;
	PList(ACK) current_acks;
	PList(ACK) current_dsacks;
	double oldest_rexmit_ts;
	double last_ack;
	bool is_spurious;

	//If a rtt estimate did not exist at the time of the retransmission, use the
	//  peer minimum rtt estimate that existed over the entire connection
	loop_over_list(rexmits, x) {
		if (IS_UNDEFINED(rexmits[x]->rtt2)) {
			rexmits[x]->rtt2 = peer->minRTT;
			rexmits[x]->rttvar = (peer->minRTT / 2.0);
		}
		rexmits[x]->necessary = false;
		rexmits[x]->confidence = UNDEFINED;
	}

	//If a rtt estimate did not exist at the time of the acknowledgement,use the
	//  minimum rtt estimate that existed over the entire connection
	loop_over_list(acks, y) {
		if (IS_UNDEFINED(acks[y]->rtt1)) {
			acks[y]->rtt1 = minRTT;
			acks[y]->rttvar = (minRTT / 2.0);
		}
		acks[y]->lost = false;
	}

	loop_over_list(dsacks, z) {
		if (IS_UNDEFINED(dsacks[z]->rtt1)) {
			dsacks[z]->rtt1 = minRTT;
			dsacks[z]->rttvar = (minRTT / 2.0);
		}
		dsacks[z]->lost = false;
	}

	while (rexmits.length() > 0) {
		is_spurious = false;
		current_acks.clear();
		current_rexmits.clear();
		current_dsacks.clear();
		seg = rexmits[0];
		oldest_rexmit_ts = seg->timestamp;

		//Get all of the rexmits that will need to be removed after this check.
		//  place them into the current_rexmits list
		loop_over_list(rexmits, i) {
			if (seg->min == rexmits[i]->min) {
				current_rexmits.insert(rexmits[i]);
				if (rexmits[i]->timestamp
						> oldest_rexmit_ts|| IS_UNDEFINED(oldest_rexmit_ts)) {
					oldest_rexmit_ts = rexmits[i]->timestamp;
				}
			}
		}

		last_ack = UNDEFINED;

		//Find all acknowledgements that acknowledge these rexmits, not including
		//  any acknowledgement that is older than an expected rtt for an ack for
		//  the last rexmit
		loop_over_list(acks, k) {
			if (acks[k]->lost)
				continue;

			/*&& acks[k]->timestamp <= (oldest_rexmit_ts + acks[k]->rtt1 + acks[k]->rttvar)*/
			if (sequenceWrapLtEq(seg->to_ack, acks[k]->ack_seq)) {
				current_acks.insert(acks[k]);
				if (IS_UNDEFINED(last_ack) || last_ack < acks[k]->timestamp)
					last_ack = acks[k]->timestamp;
			}
		}

		if (current_acks.length() == 0) {
			for (k = 0; k < acks.length(); k++) {
				if (acks[k]->lost)
					continue;

				if (sequenceWrapLtEq(seg->min, acks[k]->ack_seq))
					current_acks.insert(acks[k]);
			}
			last_ack = acks[0]->timestamp;
		}

		for (k = 0; k < dsacks.length(); k++) {
			if (dsacks[k]->lost)
				continue;

			/*&& dsacks[k]->timestamp <= (oldest_rexmit_ts + dsacks[k]->rtt1 + dsacks[k]->rttvar)*/
			if (dsacks[k]->ack_seq == seg->min) {
				current_dsacks.insert(dsacks[k]);
			}
		}
		//It is really only possible to determine retransmissions such that only
		//  one retransmission took place and the following conditions do not
		//  occur
		//A dsack did not exist for the segment and thus it is highly likely
		//  that the first packet did not reach the destination and this was
		//  not spurious or the second packet was never received either

		//If the original transmission time is undefined then the analyzer
		//  did not observe the original packet or the retransmission is a
		//  conglomeration of multiple segments and this is not an isolated
		//  loss event.
		if (current_rexmits.length() == 1) {
			SEGMENT* retransmission = current_rexmits[0];

			if (current_dsacks.length() > 0 && current_rexmits.length() == 1) {
				//The only retransmission was unnecessary. It is likely that the ack
				//  was delayed at some point and it was unnecessary to retransmit
				//  this segment

				is_spurious = true;

				//Otherwise, as more retransmissions take place, it is much more likely
				//  to be a congestion problem and much less likely to be spurious
				//} else if( current_dsacks.length() == 0 && dsacks.length() > 0 ) {
				//A dsack did not exist for this and thus it is highly likely that
				//  the first packet did not reach the destination and this was
				//  not spurious or the second packet was never received either

				//no change
				//} else if( IS_UNDEFINED(retransmission->original) ) {
				//If this is true, then we never observed the original packet and
				//  it is most likely that this is not spurious

				//no change
			} else if (current_acks.length() > 0
					&& !IS_UNDEFINED(retransmission->original)
					&& !(current_dsacks.length() == 0 && dsacks.length() > 0)) {
				ACK* acknowledgement = current_acks[0];

				//Estimate the time that each respective item was 'generated' by
				//  the respective endpoints. Then push the items toward the worst
				//  case by advancing the estimated ack by the variance of the round-trip
				//  time associated with the endpoint of the ack to estimate the
				//  latest possible 'generation' time for the acknowledgement.
				//  Do the opposite for the retransmission so that it is given the
				//  earliest possible generation time. This gives the rarest case and
				//  it is most likely that anything determined to be spurious by
				//  these values is actually spurious.
				double estimated_ack_transmission_time =
						acknowledgement->timestamp
								- (0.5 * retransmission->rtt2)
								+ retransmission->rttvar;
				double estimated_rexmit_transmission_time =
						retransmission->timestamp
								- (0.5 * acknowledgement->rtt1)
								- acknowledgement->rttvar;

				if (acknowledgement->timestamp < retransmission->timestamp) {
					is_spurious = true;
				} else if (estimated_ack_transmission_time
						< estimated_rexmit_transmission_time) {
					//is_spurious = true;
				}
			}
			//Was this segment spurious?
			if (is_spurious)
				throwSpuriousRetransmissionEvent(retransmission->min,
						retransmission->timestamp, REXMIT_UNKNOWN,
						RTYPE_UNKNOWN, UNDEFINED);
		} else if (current_rexmits.length() > 1) {
			SEGMENT* retransmission = current_rexmits[0];
			if (current_dsacks.length() >= 1)
				throwSpuriousRetransmissionEvent(retransmission->min,
						retransmission->timestamp, REXMIT_UNKNOWN,
						RTYPE_UNKNOWN, UNDEFINED);

		}

		//Once finished with this segment, remove other occurrences of this segment
		//  from the list.
		loop_over_list(current_rexmits, j)
		{
			rexmits.remove(current_rexmits[j]);
			delete current_rexmits[j];
		}

	}
}

DuplicateAck* TCPRS_Endpoint::findDupAck(SequenceRange* seq, HashKey* key,
		Segment* packet) {
	if (IS_UNDEFINED(peer->rtt))
		return NULL;

	uint32 seq_to_find = seq->min;
	DuplicateAck* tmp = NULL;
	IterCookie* d = NULL;
	DuplicateAck* iter = NULL;
	HashKey *z = NULL;

	double target = current_time - peer->rtt;
	double lower_bound = target - peer->rttvar;
	double upper_bound = target + peer->rttvar;

	double global_best_proximity = UNDEFINED;  //global best value for proximity
	double best_proximity = UNDEFINED;  //local best value for proximity
	double tmp_proximity = UNDEFINED;   //tmp variable for the proximity value

	d = duplicateAcknowledgments.InitForIteration();
	while ((iter = (DuplicateAck *) (peer->duplicateAcknowledgments.NextEntry(z,
			d, 1)))) {

		if (iter->getSeq() <= seq_to_find) {
			if (iter->getLast() < lower_bound) {
				best_proximity = (target - iter->getLast())
						* (target - iter->getLast());
			} else if (iter->getFirst() > upper_bound) {
				best_proximity = (target - iter->getFirst())
						* (target - iter->getFirst());
			} else {
				best_proximity = UNDEFINED;
				uint32 i_to_end = (
						(iter->getDupCount() >= ACK_COUNT) ?
								ACK_COUNT : iter->getDupCount());
				for (unsigned int i = 0; i < i_to_end; i++) {
					tmp_proximity = (target - iter->getTS(i))
							* (target - iter->getTS(i));
					if (tmp_proximity
							< best_proximity|| IS_UNDEFINED(best_proximity))
						best_proximity = tmp_proximity;
				}
			}

			if ((best_proximity < global_best_proximity && best_proximity > 0.0)
					|| IS_UNDEFINED(global_best_proximity)) {
				tmp = iter;
				global_best_proximity = best_proximity;
			}
		}
		best_proximity = UNDEFINED;
		tmp_proximity = UNDEFINED;
		delete z;
	}
	//free(d);

	return tmp;
}

void TCPRS_Endpoint::sequenceGapCheck(SequenceRange* sequence,
		Segment* segment, uint32 ts, HashKey* key) {
	//Lets detect a gap in the transmitted sequence space. If a gap is
	//  detected, lets record the gap as a packet sequence range from the
	//  highest observed sequence from the sender and the bottom of the sequence
	//  range of the packet that is currently being observed. The roundtrip
	//  time and timestamp of the gap should be noted to attempt

	//A valid rtt sample does not exist. It is not possible to make any assumptions
	//  about the packet considering the lack of information. This packet will
	//  be considered ambiguous
	if (IS_UNDEFINED(endpointGapInfo.roundtrip) && !hasPathRTTEstimate())
		return;

	if (segment->getOrdering() == ORDERING_UNKNOWN) {
		//If we are performing a gap check, lets update the floor of the gap to
		//  the highest acknowledged sequence from the peer
		endpointGapInfo.min = peer->getHighestAck();
		//If the gap has been acknowledged by the peer endpoint, show that the
		//  gap has been resolved
		if (endpointGapInfo.min > endpointGapInfo.to_ack) {
			endpointGapInfo.to_ack = endpointGapInfo.min;
		} else {
			//If the sequence we are observing fits inside the current gap, lets see
			//  if the packet is an out of order packet or retransmission
			if ((sequenceWrapLtEq(endpointGapInfo.min, sequence->min)
					&& sequenceWrapLt(sequence->min, endpointGapInfo.to_ack))
					&& (sequenceWrapLt(endpointGapInfo.min, sequence->to_ack)
							&& sequenceWrapLtEq(sequence->to_ack,
									endpointGapInfo.to_ack))) {
				double gaprtt = endpointGapInfo.roundtrip;
				double gaprttvar = endpointGapInfo.roundtrip / 2.0;
				double dt = current_time - endpointGapInfo.timestamp;
				double score;
				double proximity;


				//If we did not have a round trip time when the gap was detected, use
				//  the current estimate.
				if (IS_UNDEFINED(gaprtt) && hasPathRTTEstimate()) {
					gaprtt = getPathRTTEstimate();
					gaprttvar = getPathRTTVariance();
				}

				/* Basic proximity formula to determine how close the reordering was to the round trip time
				 *
				 * We would expect this value to be very low for a real reordering in practice. As dt -> 0,
				 *   the proximity should approach 1. Since we are attempting to see how close the round trip
				 *   time was to the reordering, and we assume that anything past the round trip time is a
				 *   retransmission, we need to invert the score by subtracting it from 1.
				 */
				if (dt > (gaprtt - gaprttvar)) {
					score = 1.0;
				} else {
					proximity = (1.0 - dt/(gaprtt - gaprttvar));
					score = 1.0 - (proximity * proximity);
				}

				if (score <= 0.25) {
					//assume this was out of order because it arrived within 1 rtt of
					//  the gap was detected
					processOutOfOrderEvent(segment);
					throwReorderingEvent(sequence->min,
							dt, gaprtt,
							endpointGapInfo.segment_difference);
					TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected reordering via gap seq=%u gap=%f dt=%f var=%f score=%f", sequence->min, gaprtt, dt, getPathRTTVariance(), score);
				} else if (score >= 0.75) { //This was rtt when it should have been gaprtt.
					//The gap was detected over 1 round trip time ago. This is likely a retransmission
					processRetransmissionEvent(segment, key, sequence, ts,
							REXMIT_GAP);
					TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected retransmission via gap seq=%u gap=%f dt=%f var=%f score=%f", sequence->min, gaprtt, dt, getPathRTTVariance(), score);

				}
			}
		}
	}
}

void TCPRS_Endpoint::sequenceAckCheck(SequenceRange* sequence,
		Segment* segment, HashKey* key, uint32 normalized_ack_seq) {
	if (segment->getOrdering() == ORDERING_UNKNOWN) {
		//If this packet has an ack sequence that is higher than previously
		//  observed packets, then this must be a retransmission due to the
		//  monotonically increasing property of acks
		if (sequenceWrapLt(highestAcknowledgement, normalized_ack_seq)) {
			processRetransmissionEvent(segment, key, sequence, 0, REXMIT_ACK);
			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected retransmission via ack", sequence->min);
		} else if (sequenceWrapLt(normalized_ack_seq, highestAcknowledgement)) {
			//If this packet is has an ack that came before the highest ack
			//  that has been observed , this packet is definately out of order
			processOutOfOrderEvent(segment);
			throwReorderingEvent(sequence->min, 0, 0, 0);
			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected reordering via ack seq=%u", sequence->min);
		}
	}
}

void TCPRS_Endpoint::sequenceTimestampCheck(SequenceRange* sequence,
		Segment* segment, uint32 ts, HashKey* key) {
	if (analyzer->TSOptionEnabled()
			&& segment->getOrdering() == ORDERING_UNKNOWN) {
		if (sequenceWrapLt(getTSVal(), ts)) {

			//The timestamp of this packet is later than the last observed
			//  value of the timestamp. This packet must be a retransmission
			processRetransmissionEvent(segment, key, sequence, ts,
					REXMIT_TIMESTAMP);
			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected retransmission via timestamp seq=%u", sequence->min);
		} else if (sequenceWrapLt(ts, getTSVal())) {

			//The timestamp of this packet is earlier than the last observed
			// value of the timestamp. This packet is out of order.
			processOutOfOrderEvent(segment);
			throwReorderingEvent(sequence->min, 0, 0, 0);
			TCPRS_DEBUG_MSG(LVL_1, CAT_TESTING, "detected reordering via timestamp seq=%u", sequence->min);

		}
		//else, timestamps are not granular enough to tell if this is
		//  out of order or a retransmission.
	}
}

//If this sequence number has an associated expected ack, grab the
//  packet associated with the sequence range. set the packet as a
//  fast rtx
//Valgrind Safe
void TCPRS_Endpoint::setPacketAsFastRTX(uint32 sequence) {
	SequenceRange *range = peer->getAckRange(sequence);
	if (range) {
		HashKey* key = new HashKey((uint32) (range->to_ack));
		Segment* packet = (Segment*) peer->expectedAcks.Lookup(key);
		if (packet) {
			packet->setFastRTX();
		}
		delete key;
	}
	range = NULL;
}

//Valgrind Safe
/* *****************************************************************************
 * Removes sequence ranges that are going to be acknowledged by this seq number
 * ****************************************************************************/
Segment* TCPRS_Endpoint::acknowledgeSequences(uint32 sequence,
		double acknowledged_time) {
	Segment *segment = NULL;
	Segment *ret = NULL;
	bool bad_sample = false;
	SequenceRange *range_key = outstandingData.get();
	//  This is the cumulative acknowledgement
	while (range_key
			&& Sequence_number_comparison(range_key->to_ack, sequence) < 1) {
		segment = removeSequenceNumber(range_key->to_ack);

		//If a packet in this cumulative acknowledgement is a retransmission, or
		//  an ambiguous reordered segment, this will throw off the estimation of the RTT
		//  Discard the packet at the end rather than returning it to perform a
		//  RTT sample
		if (segment) {
			segment->setAckReceivedTime(acknowledged_time);

			if ((segment->getOrdering() == ORDERING_RETRANSMISSION)
					|| (segment->getOrdering() == ORDERING_AMBIGUOUS))
				bad_sample = true;

			if (!bad_sample) {
				TCPRS_DEBUG_MSG(LVL_7,CAT_RTT,"time sent=%f time_acked=%f seq=%u rtt=%f", segment->getPacketSentTimestamp(), acknowledged_time, range_key->min, segment->RTT());
				if (ret) {

					if (ret->RTT() > segment->RTT()) {
						delete ret;
						ret = segment;
						TCPRS_DEBUG_MSG(LVL_7,CAT_RTT,"New min RTT observed for ack %u is %f", range_key->min, segment->RTT());
					} else {
						delete segment;
					}
				} else {
					TCPRS_DEBUG_MSG(LVL_7,CAT_RTT,"New min RTT observed for ack %u is %f", range_key->min, segment->RTT());
					ret = segment;
				}
			} else {
				delete segment;
			}
			segment = NULL;
		}

		delete range_key;
		range_key = outstandingData.get();
	}

	//If a segment is outstanding but it is not part of this acknowledgement,
	// then it needs to be placed into the list again.
	if (range_key
			&& Sequence_number_comparison(range_key->to_ack, sequence) == 1) {
		outstandingData.sortedinsert(range_key,
				Reverse_sequence_range_comparison);
		range_key = NULL;
	} else if (range_key) {
		delete range_key;
		range_key = NULL;
	}

	if (ret && bad_sample) {
		delete ret;
		ret = NULL;
	}

	if (ret) {
		TCPRS_DEBUG_MSG(LVL_4,CAT_RTT, "%f is the rtt for this RTT sample", ret->RTT());
	}
	//RFC 2988
	/* (5.2) When all outstanding data has been acknowledged, turn off the
	 retransmission timer. */
	if (!hasOutstandingData())
		rtoTimer.turnOff();

	return ret;
}

void TCPRS_Endpoint::setLife(RespState state) {
	//If no change in the state of the connection, just exit
	//  return if someone attempts to use the third state, "PSEUDO_DEAD"
	if (responseState == state || state == RSTATE_OBSERVING)
		return;

	if (state == RSTATE_ENDPOINT_DEAD) {
		deadSegmentCount++;
		//First time observing a retranmission so lets record the time and observe
		if (responseState == RSTATE_ENDPOINT_ALIVE) {
			deadConnectionDiedTS = current_time;
			responseState = RSTATE_OBSERVING;

			//Two retransmissions have occurred without response of any kind from
			//  the other endpoint ... lets officially consider it dead;
		} else if (responseState == RSTATE_OBSERVING && deadSegmentCount >= 2) {
			responseState = RSTATE_ENDPOINT_DEAD;
		}
		// We have finally received a response from the connection
	} else if (state == RSTATE_ENDPOINT_ALIVE) {
		deadSegmentCount = 0;
		//If the connection used to be *dead*, record the duration for which it
		//  was unresponsive.
		if (responseState == RSTATE_ENDPOINT_DEAD) {
			double* t = new double;
			if (t) {
				*t = current_time - deadConnectionDiedTS;

				//If the duration of the deadstate is less than the estimated
				//   rtt, then it is safe to assume that the other
				//   endpoint did not have sufficient amount of time to respond.
				if ((getPathRTTEstimate()) <= *t && *t > 0) {
					timeouts.append(t);
					throwConnectionDeadEvent(*t);
				} else {
					delete t;
				}
			}
		}
		responseState = state;
	}
}

void TCPRS_Endpoint::processOutstandingData(uint32 seq_to_ack) {
	//If the connection is on the 3WHS, closing or has too few packets to observe
	//  a change in the advertised window, then return
	//Also ensures that this packet is not a syn or fin
	if (congestionState == CONGESTION_3WHS
			|| congestionState == CONGESTION_CONN_CLOSE
			|| getRecoveryState() != RECOVERY_NORMAL || segmentCount <= 2)
		return;

	double elapsed_time = current_time - deltaOutstandingData.timestamp;

	//If there is not an estimate for both sides, exit
	//If owin < 0 occurs, it is because we are no longer seeing data packets from the
	//  sender and they are being captured elsewhere
	//If elapsed_time < 0 occurs, it is because the trace reordered. This should
	//  never happen
	if (!hasPathRTTEstimate() || (getHighestAck() < peer->getHighestAck())
			|| (IS_UNDEFINED(elapsed_time)))
		return;

	int rwin = peer->getWindowSize();
	int64 owin = getHighestSeq() - peer->getHighestAck();

	//If this is a new local maxima value for outstanding data, record it.
	if (owin > deltaOutstandingData.curr_outstanding)
		deltaOutstandingData.curr_outstanding = owin;

	double estimated_rtt = getPathRTTEstimate();

	//If the estimated rtt is arbitrarily small, lets estimate growth of outstanding
	//  data once every millisecond
	if (estimated_rtt < 0.001)
		estimated_rtt = 0.001;

	if (elapsed_time > estimated_rtt) {

		int64 change = (int64) deltaOutstandingData.curr_outstanding
				- (int64) deltaOutstandingData.prev_outstanding;
		if (owin == 0 && deltaOutstandingData.prev_outstanding == 0) {
			//The connection has sat idle with no packets flowing for the last
			//  two round trip times. Lets declare the connection to be idle.
			setState(CONGESTION_IDLE);

		} else {
			int64 totalChange = change + deltaOutstandingData.prev_change;

			//If the connection is increasing the outstanding data at a rate
			//  somewhere between half the mss and 2 times the mss, or a retransmission
			//  has been observed within the last two round trip times, then it
			//  is assumed that the connection is exhibiting behavior expected for
			//  congestion avoidance

			if ((totalChange > 0 && totalChange <= (2 * getMSS()))
					|| (deltaOutstandingData.rtx_timestamp > 0
							&& ((current_time
									- deltaOutstandingData.rtx_timestamp)
									< (2 * estimated_rtt)))) {
				setState(CONGESTION_AVOIDANCE);
			} else if (totalChange < 0) {
				if (owin - rwin < (getMSS() * 2))
					setState(CONGESTION_WINDOW_LIMITED);
				else if (owin == rwin)
					setState(CONGESTION_ZERO_WINDOW);
				else
					setState(CONGESTION_STEADY);
			} else {
				setState(CONGESTION_SLOW_START);
			}
		}

		deltaOutstandingData.timestamp = current_time;
		deltaOutstandingData.roundtrip = estimated_rtt;
		deltaOutstandingData.prev_outstanding =
				deltaOutstandingData.curr_outstanding;
		deltaOutstandingData.curr_outstanding = owin;
		deltaOutstandingData.prev_change = change;
	}
}

/* *****************************************************************************
 *  This marks the sections of code that are complete.
 *
 *
 *
 * ****************************************************************************/
//Valgrind Safe
bool TCPRS_Endpoint::isDuplicateAck(uint32 seq_to_ack, uint32 len,
		bool IsSyn, bool IsFin) {
	/*DUPLICATE ACKNOWLEDGMENT: An acknowledgment is considered a
	 "duplicate" in the following algorithms when (a) the receiver of
	 the ACK has outstanding data, (b) the incoming acknowledgment
	 carries no data, (c) the SYN and FIN bits are both off, (d) the
	 acknowledgment number is equal to the greatest acknowledgment
	 received on the given connection (TCP.UNA from [RFC793]) and (e)
	 the advertised window in the incoming acknowledgment equals the
	 advertised window in the last incoming acknowledgment.

	 Above material directly taken from [RFC5681]*/

	// A: peer->HasOutstandingData()
	// B: len == 0
	// C: !IsSyn && !IsFin
	// D: seq_to_ack == highest_ack
	// E: WindowSize() == prev_window
	if (peer->hasOutstandingData() && len == 0 && !IsSyn && !IsFin
			&& seq_to_ack == highestAcknowledgement
			&& getWindowSize() == prevWindow) {
		//This is obviously a duplicate acknowledgement.
		insertDupAck(seq_to_ack);
		return true;
	} else if (seq_to_ack != highestAcknowledgement) {
		//The response was delayed and was not received for some time.
		//  During this delay, multiple packets may or may not have been sent and
		//  this should not infer that the endpoint was dead.
		peer->responseState = RSTATE_ENDPOINT_ALIVE;
	}

	//for now, assuming that this is arbitrarily close to the endpoint
	double estimated_net_time = current_time;

	//If a rtt estimate exists, assume symmetry to make this easy for now.
	//Changed from peer->rtt to rtt because this should be using the round trip
	// time of the endpoint to determine when the segment/ack should be arriving
	if (!IS_UNDEFINED(rtt))
		estimated_net_time += (0.5 * (rtt - rttvar));

	peer->rtoTimer.updateRTOTimer(estimated_net_time, peer->estimatedRTO);

	return false;
}

void TCPRS_Endpoint::processAmbigousReordering(Segment* segment,
		SequenceRange* sequence) {
	segment->setOrdering(ORDERING_AMBIGUOUS);
	peer->recordOutOfOrder();
	throwAmbiguousReorderingEvent(sequence->min,
			(current_time - endpointGapInfo.timestamp),
			endpointGapInfo.segment_difference);
}

void TCPRS_Endpoint::processRTO(Segment* packet, SequenceRange* seq,
		RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype,
		double confidence) {

	TCPRS_DEBUG_MSG(LVL_1, CAT_RECOVERY, "recovery sequence set by sequence=%i to seq=%i", seq->min, highestSequence);
	recoverySequence = highestSequence;
	recordRTO();
	if (packet->RTXCount() >= 3)
		setState(CONGESTION_REPEATED_RETRANS);

	//If the packet is a syn , we can get an idea of the initial rto
	//  based on how long it takes before we see the first retransmission,
	//  if any exists.
	if (packet->isSYN() && current_time != packet->getPacketSentTimestamp()) {
		estimatedRTO = (current_time - packet->getPacketSentTimestamp());

		//If this is the first time this syn is being retransmitted, this is the
		//  initial rto and we want to capture that.
		if(packet->RTXCount() == 1) {
			val_list *vl = new val_list;

			vl->append(analyzer->BuildConnVal());
			vl->append(new Val(current_time, TYPE_TIME));
			vl->append(new Val(estimatedRTO, TYPE_DOUBLE));
			vl->append(new Val(isOrig(),TYPE_BOOL));

			analyzer->ConnectionEvent(conn_initial_rto, vl);
		}
	}

	throwRetransmissionEvent(packet, seq->min, reason, rtype, confidence);
	setRecoveryState(RECOVERY_RTO);

	//if( getLikelyMaxRTO(previousRTO, rtoTimer.elapsedTime(current_time)) > 0.0 )
	//    estimatedRTO = getLikelyMaxRTO(previousRTO, rtoTimer.elapsedTime(current_time));
	//else
	estimatedRTO *= 2.0;     //RTO Backoff

	//need to skew the time a little for this case same as above...
	//! Important
	rtoTimer.updateRTOTimer(current_time, estimatedRTO);
}

void TCPRS_Endpoint::processFastRetransmission(Segment* segment,
		SequenceRange* seq, RETRANSMISSION_REASON_CODE reason,
		RETRANSMISSION_TYPE_CODE rtype, double confidence) {
	segment->setFastRTX();
	recordFastRTX();
	if (segment->RTXCount() >= 3)
		setState(CONGESTION_REPEATED_RETRANS);

	throwRetransmissionEvent(segment, seq->min, reason, rtype, confidence);

	setRecoveryState(RECOVERY_FAST_RTX);
}

//Update the information regarding the RTO and the retransmission timeout. Until
//  there is a valid rtt estimate for the whole path, leave the estimated RTO as
//  is because we cannot appropriately estimate the rto without it

//As defined in RFC 2988
void TCPRS_Endpoint::updateRTT(double val) {
	//  This indicated the first RTT sampling
	if (IS_UNDEFINED(rtt)) {
		rtt = val;
		rttvar = val / 2.0;
	} else {
		rttvar = ((1 - BETA_SRTT) * rttvar) + (BETA_SRTT * fabs(rtt - val));
		rtt = ((1 - ALPHA_SRTT) * rtt) + (ALPHA_SRTT * val);
	}

	if (hasPathRTTEstimate()) {
		//Assuming the path is symmetrical
		estimatedRTO = (rtt + peer->rtt) + (K_CONST * (peer->rttvar + rttvar)); //draft paxson tcp rto calculation
		if (estimatedRTO < 0.200 /*milliseconds, linux minimum*/)
			estimatedRTO = 0.200;
	}

	TCPRS_DEBUG_MSG(PEDANTIC,CAT_RTT,"orig=%i rtt=%.8f rttvar=%.8f erto=%.8f rtt_sample=%.8f",isOrig(), rtt, rttvar, estimatedRTO, val);


	//Get a minimum rtt for this half of the path
	if (minRTT > rtt || IS_UNDEFINED(minRTT))
		minRTT = rtt;
}

void TCPRS_Endpoint::updateSequenceGap(uint32 seq) {
	//If the existing gap has been acknowledged, this is a new gap
	endpointGapInfo.min = peer->getHighestAck();
	if (endpointGapInfo.to_ack <= endpointGapInfo.min) {

		//The minimum of this seqment will act as the roof of the gap
		endpointGapInfo.to_ack = seq;
		endpointGapInfo.to_ack = endpointGapInfo.to_ack;
		//The previous 'highest observed sequence sent'  will serve as
		//  the floor of the gap
		endpointGapInfo.min = getHighestSeq();

		//If there is an existing SRTT estimate, use it.
		//gap.roundtrip = ((HasSRTTEstimate()) ? GetSRTTEstimate() : UNDEFINED);
		endpointGapInfo.roundtrip = (
				(hasPathRTTEstimate()) ? getPathRTTEstimate() : UNDEFINED);
		endpointGapInfo.segment_difference = 0; //Assume the gap is atleast one segment
		//  This is incremented at the end
		//  of the function.
		endpointGapInfo.timestamp = current_time; //Use the current network time to detect start of the gap
	} else {
		//This is an update to the current gap. This occurs when multiple
		//  packets have been re-ordered

		//If the gap ceiling is higher than what was previously observed,
		//  record it

		//This can occur if multiple packets are re-ordered creating
		//  multiple sequence gaps. Note: This will not affect packets
		//  that have already been previously observed.
		endpointGapInfo.to_ack = (
				(seq > endpointGapInfo.to_ack) ? seq : endpointGapInfo.to_ack);

	}
}

//Example(true):
//Xi = 42949348957
//Xf = 10020
inline bool TCPRS_Endpoint::sequenceWrap(uint32 Xi, uint32 Xf) {
	//If the sequence has wrapped around, return true, else return false;
	return (Xi > Xf && ((Xi) - Xf) > (SEQUENCE_MAX >> 1));
}

inline bool TCPRS_Endpoint::sequenceWrapLtEq(uint32 Xi, uint32 Xf) {
	return ((sequenceWrapLt(Xi, Xf)) || (Xi == Xf));
}

//Function checks to see if sequence Xi came before sequence Xf by checking for
//  Xi < Xf with no sequence wrap and Xi > Xf with sequence wrap
inline bool TCPRS_Endpoint::sequenceWrapLt(uint32 Xi, uint32 Xf) {
	return ((Xi < Xf) ? !sequenceWrap(Xf, Xi) : sequenceWrap(Xi, Xf));
}

void TCPRS_Endpoint::setRecoveryState(RecoveryState state) {
	recoveryState = state;
}

void TCPRS_Endpoint::throwCongestionStateChangeEvent(CongestionState prev,
		CongestionState current) {
	if (conn_state_change) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(prev, TYPE_INT));
		vl->append(new Val(current, TYPE_INT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));

		analyzer->ConnectionEvent(conn_state_change, vl);
	}
}

void TCPRS_Endpoint::throwRetransmissionEvent(Segment* segment, uint32 seq,
		RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype,
		double confidence) {

	if (conn_rexmit) {
		double est_rtt = 0.0;
		if (hasPathRTTEstimate())
			est_rtt = getPathRTTEstimate();

		val_list *vl = new val_list;

		int flags = 0;
		if(segment->isFIN())
			flags |= TH_FIN;

		if(segment->isRST())
			flags |= TH_RST;

		if(segment->isSYN())
			flags |= TH_SYN;

		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(est_rtt, TYPE_DOUBLE));
		vl->append(new Val(congestionState, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));
		vl->append(new Val(reason, TYPE_INT));
		vl->append(new Val(rtype, TYPE_INT));
		vl->append(new Val(confidence, TYPE_DOUBLE));
		vl->append(new Val(flags, TYPE_INT));

		analyzer->ConnectionEvent(conn_rexmit, vl);
	}
}

void TCPRS_Endpoint::throwSpuriousRetransmissionEvent(uint32 seq, double ts,
		RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype,
		double confidence) {
	if (conn_spurious_dsack) {
		val_list *vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(ts, TYPE_TIME));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(confidence, TYPE_DOUBLE));
		vl->append(new Val(congestionState, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));
		vl->append(new Val(reason, TYPE_INT));
		vl->append(new Val(rtype, TYPE_INT));

		analyzer->ConnectionEvent(conn_spurious_dsack, vl);
	}
}

void TCPRS_Endpoint::throwDuplicateAckEvent(uint32 seq, uint32 num_rtx) {
	if (tcp_dup_ack) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(seq + startSeq(), TYPE_INT));
		vl->append(new Val(num_rtx, TYPE_INT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));

		analyzer->ConnectionEvent(tcp_dup_ack, vl);
	}
}

void TCPRS_Endpoint::throwConnectionDeadEvent(double duration) {
	if (conn_dead_event) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(duration, TYPE_DOUBLE));
		vl->append(new Val(congestionState, TYPE_INT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));

		analyzer->ConnectionEvent(conn_dead_event, vl);
	}
}

void TCPRS_Endpoint::throwReorderingEvent(uint32 seq, double gap, double rtt,
		uint32 seq_difference) {
	if (conn_ooo_event) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(gap, TYPE_DOUBLE));
		vl->append(new Val(rtt, TYPE_DOUBLE));
		vl->append(new Val(seq_difference, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));

		analyzer->ConnectionEvent(conn_ooo_event, vl);
	}
}

void TCPRS_Endpoint::throwAmbiguousReorderingEvent(uint32 seq, double gap,
		uint32 seq_difference) {
	if (conn_ambi_order) {
		val_list *vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(gap, TYPE_DOUBLE));
		vl->append(new Val(seq_difference, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));

		analyzer->ConnectionEvent(conn_ambi_order, vl);
	}
}

void TCPRS_Endpoint::throwRTTEstimateEvent() {
	if (conn_rtt_estimate) {
		val_list *vl = new val_list;
		double c_rtt = (connectionOrigin ? rtt : peer->rtt);
		double s_rtt = (connectionOrigin ? peer->rtt : rtt);
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(getPathRTTEstimate(), TYPE_DOUBLE));
		vl->append(new Val(c_rtt, TYPE_DOUBLE));
		vl->append(new Val(s_rtt, TYPE_DOUBLE));

		analyzer->ConnectionEvent(conn_rtt_estimate, vl);
	}
}

void TCPRS_Endpoint::throwUnknownRetransmissionEvent(Segment* packet,
		SequenceRange* seq, RETRANSMISSION_REASON_CODE reason,
		RETRANSMISSION_TYPE_CODE type, double confidence) {
	recordRetransmission(packet->getPacketSize());

	if (packet->RTXCount() >= 3)
		setState(CONGESTION_REPEATED_RETRANS);

	throwRetransmissionEvent(packet, seq->min, reason, type, confidence);
}

void TCPRS_Endpoint::throwLimitedTransmitEvent(uint32 seq) {
	if (conn_limited_transmit) {
		double est_rtt = 0.0;
		if (hasPathRTTEstimate())
			est_rtt = getPathRTTEstimate();

		val_list *vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(est_rtt, TYPE_DOUBLE));
		vl->append(new Val(congestionState, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));

		analyzer->ConnectionEvent(conn_limited_transmit, vl);
	}
}

void TCPRS_Endpoint::throwFastRecoveryTransmitEvent(uint32 seq) {
	if (conn_fast_recovery) {
		double est_rtt = 0.0;
		if (hasPathRTTEstimate())
			est_rtt = getPathRTTEstimate();

		val_list *vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(current_time, TYPE_TIME));
		vl->append(new Val(seq + startSeq(), TYPE_COUNT));
		vl->append(new Val(connectionOrigin, TYPE_BOOL));
		vl->append(new Val(est_rtt, TYPE_DOUBLE));
		vl->append(new Val(congestionState, TYPE_INT));
		vl->append(new Val(startSeq(), TYPE_COUNT));
		vl->append(new Val(peer->highestAcknowledgement, TYPE_COUNT));
		vl->append(new Val(highestSequence, TYPE_COUNT));

		analyzer->ConnectionEvent(conn_fast_recovery, vl);
	}
}

void TCPRS_Endpoint::processACK(const uint32 normalizedAckSequence,
		const uint32 len, TCP_Flags& flags, const struct tcphdr* tp) {

	TCPRS_DEBUG_MSG(PEDANTIC, CAT_MISC,
			"processing acknowledgement for sequence %u at time %f",
			normalizedAckSequence, current_time);

	isDuplicateAck(normalizedAckSequence, len, flags.SYN(), flags.FIN());

	ackTimestamps.addEntry(new double(current_time));
	ackCount++; //Probably not necessary

	// this is the syn-ack.  the normalized syn-ack seq# is always 1
	bool is_syn_ack = (!doneSYNACK() && normalizedAckSequence == 1);

	if (is_syn_ack) {
		setDoneSYNACK(true);
	}

	if (normalizedAckSequence >= peer->getRecoverySeq()
			&& peer->getRecoveryState() != RECOVERY_NORMAL) {

		if (peer->getRecoveryState() == RECOVERY_RTO)
			peer->setState(CONGESTION_SLOW_START);
		TCPRS_DEBUG_MSG(LVL_1, CAT_RECOVERY, "restored normal state seq=%i ts=%f peer->recoveryseq=%i",
				normalizedAckSequence, current_time, peer->getRecoverySeq());
		peer->restoreNormalRecovery();
	}

	//The packet up to normalized_ack_seq have made it to the endpoint and back
	//to the observation point. This confirms receipt. Lets Ack the sequences.

	Segment* segment = peer->acknowledgeSequences(normalizedAckSequence,
			current_time);
	if (segment != NULL) {
		segment->setAckReceivedTime(current_time);

		peer->recordValidRTTSample();
		peer->updateRTT(segment->RTT());

		//This endpoint is the source of the connection /defined as near_src
		if (hasPathRTTEstimate())
			analyzer->EstimateMeasurementLocation();

		delete segment;
	}

	//If both endpoints have seen the handshake, new data is being acknowledged,
	//  and the endpoint state was last seen in 3WHS then update state. Do not
	//  record an initial rtt if one endpoint had to retransmit a syn packet.
	//  Only get the initial RTT from the originating endpoint so as to
	//  eliminate noise from unidirectional connections
	if (doneSYNACK() && peer->doneSYNACK() && getHighestAck() >= 1
			&& getState() == CONGESTION_3WHS && isOrig() &&
			(getRTO() == 0 && peer->getRTO() == 0)) {
		setState(CONGESTION_SLOW_START);

		//The line below is an assumption that the other side receives the acknowledgement
		peer->setState(CONGESTION_SLOW_START);
	    if (hasPathRTTEstimate()) {
	    	val_list *vl = new val_list;

	    	vl->append(analyzer->BuildConnVal());
	    	vl->append(new Val(current_time, TYPE_TIME));
	    	vl->append(new Val(getPathRTTEstimate(),TYPE_DOUBLE));
	    	vl->append(new Val(isOrig(),TYPE_BOOL));

	    	analyzer->ConnectionEvent(conn_initial_rtt, vl);
	    }
	}

}

bool TCPRS_Endpoint::isResponse(double currentTime) {
	if (IS_UNDEFINED(peer->rtt))
		return false;

	double lower_bound = (currentTime - peer->rtt) - peer->rttvar;
	double upper_bound = (currentTime - peer->rtt) + peer->rttvar;
	double min_dist = peer->rtt;
	if (min_dist < 0.001) {
		min_dist = 0.001;
		lower_bound = (currentTime - peer->rtt) - min_dist;
		upper_bound = (currentTime - peer->rtt) + min_dist;
	}

	FOR_EACH_IN_CLIST(i, peer->ackTimestamps)
	{
		if (!(peer->ackTimestamps[i])
				|| *(peer->ackTimestamps[i]) > currentTime)
			continue;

		if (lower_bound <= *(peer->ackTimestamps[i])
				&& *(peer->ackTimestamps[i]) <= upper_bound)
			return true;

		//For cases such that we are extremely close to the sender, it may be more
		//  prudent to accept cases where the turn around time is much shorter
		//  than we expect.

		if (((currentTime - *(peer->ackTimestamps[i])) < min_dist)
				&& (peer->rtt < 0.005))
			return true;

	}
	return false;
}

double getLikelyMaxRTO(double previous, double current) {
	if (IS_UNDEFINED(previous))
		return UNDEFINED;
	double rateIncrease = current / previous;
	if (((rateIncrease * 10.0) - floor(rateIncrease * 10.0)) > 0.5)
		rateIncrease = ceil(rateIncrease * 10.0) / 10.0;
	else
		rateIncrease = floor(rateIncrease * 10.0) / 10.0;
	if (previous > current && rateIncrease > 0.9) {
		return current;
	} else if (previous > current && rateIncrease <= 0.9) {
		return previous;
	} else {
		if (rateIncrease < 1.1)
			return previous;
		if (rateIncrease < 1.5)
			return previous * 1.1;
		if (rateIncrease < 2.0)
			return previous * 1.5;
	}
	return current * 0.95;
}

void TCPRS_Endpoint::processOptions(const tcphdr* tcp, TCP_Flags& flags,
		uint32 sequenceToAcknowledge) {
	// Parse TCP options.
	u_char* options = (u_char*) tcp + sizeof(struct tcphdr);
	u_char* opt_end = (u_char*) tcp + tcp->th_off * 4;
	uint32 high_seq = 0;
	uint32 low_seq = 0;
	uint32 max_seq = 0;
	peer->clearSACKBytes();
	peer->clearSACKSegments();

	while (options < opt_end) {
		unsigned int opt = options[0];

		if (opt == TCPOPT_EOL)
			// All done - could flag if more junk left over ....
			break;

		if (opt == TCPOPT_NOP) {
			++options;
			continue;
		}

		if (options + 1 >= opt_end)
			// We've run off the end, no room for the length.
			break;

		unsigned int opt_len = options[1];

		if (options + opt_len > opt_end)
			// No room for rest of option.
			break;

		if (opt_len == 0)
			// Trashed length field.
			break;

		switch (opt) {
		case TCPOPT_SACK_PERMITTED:
			SACKEnabled = true;
			break;

		case TCPOPT_MAXSEG:
			if (opt_len < 4)
				break;	// bad length

			mss = (options[2] << 8) | options[3];
			break;

		case TCPOPT_TIMESTAMP: //TCP Timestamps
			if (opt_len < 10)
				break;	// bad length

			if (flags.ACK()) {
				sendTimestampVal = extract_uint32(options + 2);
				echoTimestampVal = extract_uint32(options + 6);
			}
			usesTimestamps = true;
			break;

		case TCPOPT_SACK:
			analyzer->sack_in_use = true;

			for (unsigned int i = 2; i < opt_len; i += 8) {
				low_seq = extract_uint32(options + i) - peer->startSeq();
				high_seq = extract_uint32(options + i + 4) - peer->startSeq();
				if (sequenceWrapLt(max_seq, high_seq))
					max_seq = high_seq;

				if (sequenceWrapLtEq(high_seq, sequenceToAcknowledge)) {
					//Add dsack to list for spurious rexmit checking later
					/*ACK* ptr = new ACK;
					 if( ptr != NULL ) {
					 ptr->ack_seq = low_seq;
					 ptr->timestamp = current_time;
					 // Changed from peer->rtt to rtt
					 ptr->rtt1 = rtt;        //Passing the expected ack rtt
					 ptr->rttvar = rttvar;   //Passing the expected ack rttvar
					 ptr->lost = false;
					 //Add this to the other endpoint so that it can perform
					 //  spurious retransmission detection.
					 peer->addDSACKToList(ptr);
					 }*/
				} else {
					peer->incrementSACKBytes(high_seq - low_seq);
					loop_over_list(peer->outstandingData, k) {
						if (peer->outstandingData[k]->min >= low_seq
								&& peer->outstandingData[k]->to_ack <= high_seq)
							peer->incrementSACKSegments();
					}

					SequenceRange* segment = new SequenceRange;
					segment->min = low_seq;
					segment->to_ack = high_seq;

					//scoreboard.addSegment( segment );
				}
			}

			if (peer->getRecoveryState() == RECOVERY_NORMAL) {
				//There is definitely three segments or more of a gap
				if ((max_seq - sequenceToAcknowledge)
						> (unsigned int) (3 * peer->getMSS())) {
					//peer->fackTimestamps.addEntry(current_time);

					peer->addForwardAckTS(current_time);
				}
			}
			break;
		case 3: // TCPOPT_WSCALE
			break;

		default:	// just skip over
			break;
		}

		options += opt_len;
	}
}


void TCPRS_Endpoint::setPeer(TCPRS_Endpoint *p)
{
	peer = p;
}

TCPRS_Endpoint* TCPRS_Endpoint::Peer()
{
	return peer;
}

void TCPRS_Endpoint::recordDupAck()
{
	numDuplicateAcks++;
}

void TCPRS_Endpoint::recordRetransmission(int len)
{
	numRexmit++;
	numRexmitBytes += len;
}

void TCPRS_Endpoint::recordSuspectSlowStart()
{
	numSlowStart++;
}

void TCPRS_Endpoint::recordFastRTX()
{
	numFastRTX++;
}

void TCPRS_Endpoint::recordRTO()
{
	numRTO++;
}

void TCPRS_Endpoint::recordOutOfOrder()
{
	numOutOfOrder++;
}

void TCPRS_Endpoint::recordValidRTTSample()
{
	rttNumValidSamples++;
}

uint32 TCPRS_Endpoint::getDupAcks()
{
	return numDuplicateAcks;
}

uint32 TCPRS_Endpoint::getRetrans()
{
	return numRexmit;
}

uint32 TCPRS_Endpoint::getRTO()
{
	return numRTO;
}

uint32 TCPRS_Endpoint::getFastRTX()
{
	return numFastRTX;
}

uint32 TCPRS_Endpoint::getOutOfOrder()
{
	return numOutOfOrder;
}

uint32 TCPRS_Endpoint::getValidRTTSampleCount()
{
	return rttNumValidSamples;
}

uint32 TCPRS_Endpoint::getRecoverySeq()
{
	return recoverySequence;
}

uint32 TCPRS_Endpoint::getLastAckSeqForGapCheck()
{
	return lastAckSeqForGapCheck;
}

// TCP_Endpoint function wrappers
uint32 TCPRS_Endpoint::startSeq()
{
	return endp->StartSeq();
}

uint32 TCPRS_Endpoint::lastSeq()
{
	return endp->LastSeq();
}

uint32 TCPRS_Endpoint::ackSeq()
{
	return endp->AckSeq();
}

// last sequence number sent including retransmissions. not the
// same as LastSeq()
uint32 TCPRS_Endpoint::lastSeqSent()
{
	return lastSequenceSent;
}

void TCPRS_Endpoint::updateLastSeqSent(uint32 seq)
{
	lastSequenceSent = seq;
}

// whether we have seen an ack for our syn.  NOTE: it's checking
// for an ack for the syn, not necessary a syn-ack (as in a 3-way
// handshake); i.e., we still use it for simultaneous connections
// (syn syn ack ack vs. syn syn-ack ack).
bool TCPRS_Endpoint::doneSYNACK()
{
	return doneSynAck;
}

void TCPRS_Endpoint::setDoneSYNACK(bool value)
{
	doneSynAck = value;
}

// last IP ID seen
void TCPRS_Endpoint::setLastID(int id)
{
	lastIPID = id;
}

int TCPRS_Endpoint::lastID()
{
	return lastIPID;
}

bool TCPRS_Endpoint::hasOutstandingData()
{
	return outstandingData.length() > 0;
}

// TTL that this endpoint sees.
int TCPRS_Endpoint::getTTL()
{
	return ttl;
}

void TCPRS_Endpoint::setTTL(int ttl_arg)
{
	ttl = ttl_arg;
}

// Code for determining the origination of the connection
bool TCPRS_Endpoint::isOrig()
{
	return connectionOrigin;
}

void TCPRS_Endpoint::setOrig(bool arg)
{
	connectionOrigin = arg;
}

// Receiver Window size
uint32 TCPRS_Endpoint::getWindowSize()
{
	return endp->window;
}

// Receiver Window Scale
int TCPRS_Endpoint::getWindowScale()
{
	return endp->window_scale;
}

int TCPRS_Endpoint::getPrevWindow()
{
	return prevWindow;
}

void TCPRS_Endpoint::updatePrevWindow()
{
	prevWindow = getWindowSize();
}

// Max Segment Size Code
void TCPRS_Endpoint::setMSS(int arg)
{
	mss = arg;
}

int TCPRS_Endpoint::getMSS()
{
	return mss;
}

void TCPRS_Endpoint::setMinRTT(double arg)
{
	if (arg < minRTT || IS_UNDEFINED(minRTT))
		minRTT = arg;
}

double TCPRS_Endpoint::getMinRTT()
{
	return minRTT;
}

void TCPRS_Endpoint::setHighestAck(uint32 arg)
{
	if (sequenceWrapLt(highestAcknowledgement, arg))
		highestAcknowledgement = arg;
}

uint32 TCPRS_Endpoint::getHighestAck()
{
	return highestAcknowledgement;
}

//Based on to-ack of range
void TCPRS_Endpoint::setHighestSeq(uint32 arg)
{
	if (sequenceWrapLt(highestSequence, arg))
		highestSequence = arg;
}

uint32 TCPRS_Endpoint::getHighestSeq()
{
	return highestSequence;
}


void TCPRS_Endpoint::incrementSegmentCount()
{
	segmentCount++;
}

int TCPRS_Endpoint::getSegmentCount()
{
	return segmentCount;
}

void TCPRS_Endpoint::setState(CongestionState c)
{
	previousCongestionState = congestionState;
	congestionState = c;
	if (previousCongestionState != congestionState)
		throwCongestionStateChangeEvent(previousCongestionState,
				congestionState);
}

CongestionState TCPRS_Endpoint::getState()
{
	return congestionState;
}

double TCPRS_Endpoint::getPathRTTEstimate()
{
	return rtt + peer->rtt;
}

double TCPRS_Endpoint::getPathRTTVariance()
{
	return rttvar + peer->rttvar;
}

bool TCPRS_Endpoint::hasPathRTTEstimate()
{
	return ((!IS_UNDEFINED(rtt)) && (!IS_UNDEFINED(peer->rtt)) );
}
double TCPRS_Endpoint::getRTT()
{
	return rtt;
}

double TCPRS_Endpoint::getRTTVariance()
{
	return rttvar;
}

RespState TCPRS_Endpoint::alive()
{
	return responseState;
}

void TCPRS_Endpoint::addTimeStamp(uint32 t)
{
	if( t > currentTSVal || sequenceWrap(currentTSVal, t) ) currentTSVal = t;
}

uint32 TCPRS_Endpoint::getTSVal()
{
	return currentTSVal;
}

bool TCPRS_Endpoint::usesTSOption()
{
	return usesTimestamps && peer->usesTimestamps;
}

void TCPRS_Endpoint::restoreOldState()
{
	congestionState = previousCongestionState;
}

RecoveryState TCPRS_Endpoint::getRecoveryState()
{
	return recoveryState;
}

void TCPRS_Endpoint::restoreNormalRecovery()
{
	setRecoveryState(RECOVERY_NORMAL);
	deltaOutstandingData.timestamp = current_time;
}

bool TCPRS_Endpoint::isSACKEnabled()
{
	return SACKEnabled;
}

void TCPRS_Endpoint::clearSACKBytes()
{
	sackedBytes = 0;
}

void TCPRS_Endpoint::incrementSACKBytes(uint32 len)
{
	sackedBytes += len;
}

void TCPRS_Endpoint::clearSACKSegments()
{
	sackedSegments = 0;
}

void TCPRS_Endpoint::incrementSACKSegments()
{
	sackedSegments++;
}

int analyzer::tcp::Sequence_number_comparison(const uint32 s1, const uint32 s2) {

	int to_return = 0;
	if (s1 < s2)
		to_return = -1;
	else if (s1 - s2 > SEQ_WRAP) // seq space wrap
		to_return = -1;
	else if (s1 > s2)
		to_return = 1;

	return to_return;
}

int analyzer::tcp::Reverse_sequence_range_comparison(const void *v1, const void *v2) {

	const SequenceRange *r1 = (const SequenceRange*) v1;
	const SequenceRange *r2 = (const SequenceRange*) v2;

	// for now, just compare based on the ack sequence number.  should be fine..
	int to_return = 0;
	if (r1->to_ack < r2->to_ack)
		to_return = -1;
	else if (r1->to_ack - r2->to_ack > SEQ_WRAP)
		to_return = -1;
	else if (r1->to_ack > r2->to_ack)
		to_return = 1;

	return to_return;
}
