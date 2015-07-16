/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */

/* *****************************************************************************
 * This line is required to obtain the TCP options from the initial syn packets.
 *
 *           redef use_connection_compressor = F;
 * ****************************************************************************/
#ifndef TCPRS_ENDPOINT_H
#define TCPRS_ENDPOINT_H

#include <queue>
#include "analyzer/protocol/tcp/TCP_Endpoint.h"
#include "List.h"
#include "Net.h"
#include "TCP.h"
#include "analyzer/protocol/tcp/TCPRS_Support.h"

namespace analyzer { namespace tcp {

class TCPRS_Endpoint {
public:
	TCPRS_Endpoint(analyzer::tcp::TCP_Endpoint *e, analyzer::tcp::TCPRS_Analyzer *a);
	~TCPRS_Endpoint();

	void DeliverSegment(int len, const u_char* data, bool is_orig, int seq,
			const IP_Hdr* ip, int caplen);

	void setPeer(TCPRS_Endpoint *p);
	TCPRS_Endpoint* Peer();

	void processACK(const uint32 normalizedAckSequence, const uint32 len,
			TCP_Flags& flags, const struct tcphdr* tp);

	void processOptions(const struct tcphdr* tcp, TCP_Flags& flags,
			const uint32 sequenceToAcknowledge);

	RecordVal* buildStats();

	void examinePotentialSpuriousRexmits();

	void recordDupAck();
	void recordRetransmission(int len);
	void recordSuspectSlowStart();
	void recordFastRTX();
	void recordRTO();
	void recordOutOfOrder();
	void recordValidRTTSample();

	uint32 getDupAcks();
	uint32 getRetrans();
	uint32 getRTO();
	uint32 getFastRTX();
	uint32 getOutOfOrder();
	uint32 getValidRTTSampleCount();
	uint32 getRecoverySeq();

	void setPacketAsFastRTX(uint32 sequence);

	void insertSequenceNumber(SequenceRange *seq, Segment *value, uint32 ts,
			uint32 normalized_ack_seq);
	void insertDupAck(uint32 seq);

	bool isDuplicateAck(uint32 seq_to_ack, uint32 len, bool IsSyn, bool IsFin);

	Segment* acknowledgeSequences(uint32 seq, double acknowledged_time);

	uint32 getLastAckSeqForGapCheck();
	void rebuildRange(SequenceRange* range);
	bool spansPreviousTX(SequenceRange* seq);

	// TCP_Endpoint function wrappers
	uint32 startSeq();
	uint32 lastSeq();
	uint32 ackSeq();

	// last sequence number sent including retransmissions. not the
	// same as LastSeq()
	uint32 lastSeqSent();
	void updateLastSeqSent(uint32 seq);

	// whether we have seen an ack for our syn.  NOTE: it's checking
	// for an ack for the syn, not necessary a syn-ack (as in a 3-way
	// handshake); i.e., we still use it for simultaneous connections
	// (syn syn ack ack vs. syn syn-ack ack).
	bool doneSYNACK();
	void setDoneSYNACK(bool value);
	// last IP ID seen
	void setLastID(int id);
	int lastID();

	bool hasOutstandingData();

	// TTL that this endpoint sees.  used by stats analyzer to estimate measurement vantage point
	int getTTL();
	void setTTL(int ttl_arg);

	// Code for determining the origination of the connection
	bool isOrig();
	void setOrig(bool arg);

	// Receiver Window size
	uint32 getWindowSize();
	// Receiver Window Scale
	int getWindowScale();
	int getPrevWindow();
	void updatePrevWindow();

	// Max Segment Size Code
	void setMSS(int arg);
	int getMSS();
	void setMinRTT(double arg);
	double getMinRTT();

	void setHighestAck(uint32 arg);
	uint32 getHighestAck();
	//Based on to-ack of range
	void setHighestSeq(uint32 arg);
	uint32 getHighestSeq();

	SequenceRange* getAckRange(bro_uint_t sequence);

	void incrementSegmentCount();
	int getSegmentCount();

	void setState(CongestionState c);

	CongestionState getState();

	void updateRTT(double val);

	double getPathRTTEstimate();
	double getPathRTTVariance();
	bool hasPathRTTEstimate();
	double getRTT();
	double getRTTVariance();

	RespState alive();
	void setLife(RespState state);

	void processOutstandingData(uint32 seq_to_ack);

	void addTimeStamp(uint32 t);

	uint32 getTSVal();
	bool usesTSOption();

	void restoreOldState();

	RecoveryState getRecoveryState();
	void restoreNormalRecovery();

	bool isSACKEnabled();

	//void addAckToList(ACK* seq) { /* acks.insert(seq); */}
	//void addDSACKToList(ACK* seq) { /* dsacks.insert(seq); */}
	//void addRexmitToList(SEGMENT* seq) { /* rexmits.insert(seq); */}

	void clearSACKBytes();
	void incrementSACKBytes(uint32 len);
	void clearSACKSegments();
	void incrementSACKSegments();

protected:

	double current_time;        //Time of the segment may differ from bro's
								// network time
	RTOTimer rtoTimer;

	uint32 highestAcknowledgement;//Highest Acknowledgement sent by this endpoint
	uint32 highestSequence;//Highest Sequence sent by this endpoint;

	uint32 prevWindow;

	uint32 prevOutstanding;
	uint32 numRTO;//Number of times that the RTO caused a rxmit
	uint32 numFastRTX;//Number of times that fast rtx was initiated
	uint32 numDuplicateAcks;//Number of times that duplicate acks were seen
	uint32 numSlowStart;//Number of times that slow start was initiated due to congestion
	uint32 segmentCount;//Number of segments sent by this endpoint
	uint32 numRexmit;//Number of segments that were retransmitted
	uint32 numRexmitBytes;//Number of bytes that were retransmitted
	uint32 numOutOfOrder;//Number of times that a segment was
						 //  out order toward this endpoint

	uint32 lastIPID;//Last observed IP address of this endpoint
	uint32 maxDataInFlight;

	double stateConfidence;

	TCPRS_Analyzer *analyzer;// associate with a TCPState_Analyzer so that we can throw events ourselves
	analyzer::tcp::TCP_Endpoint *endp;// associate with a TCP_Endpoint so that we have access to the state machine
	TCPRS_Endpoint *peer;// associate with the TCPState_Endpoint on the other side so we have access
							// to peer data structures.

	bool connectionOrigin;//Is this the original endpoint?

	bool doneSynAck;
	uint32 lastSequenceSent, lastAckSeqForGapCheck;
	uint32 ttl;
	uint32 mss;

	// keeps track of the sequence numbers for which we expect ACKs.
	// sequence number maps to a segment_State object, which has the time
	// the segment was sent, among many other things.
	Dictionary expectedAcks;

	// basically the key set for expected_acks, just sorted, and comes with ranges. (so really not the key set at all.)
	PList(SequenceRange) outstandingData;

	PList(double) timeouts;

	//Spurious Rexmit Detection
	PList(ACK) acks;
	PList(ACK) dsacks;
	PList(SEGMENT) rexmits;

	// The sequence pair should be removed once a higher sequence has been ack'd
	Dictionary duplicateAcknowledgments;

	CongestionState congestionState, previousCongestionState;

	Segment *removeSequenceNumber(uint32 seq);
	DuplicateAck *removeDuplicateAck(uint32 seq);

	double minRTT;//Minimum round-trip time observed for segments between
				  //  the observation point and this endpoint

	double lastWindowSampleTS;//timestamp for the last time the change in the
							  //  window was taken

							  //Dead Connection Variables
	RespState responseState;  //Did this connection stop responding at some point?
	uint32 deadSegmentCount;//Count of segments retransmitted since last observed
	//  contact from the other endpoint
	double deadConnectionDiedTS;//The time at which the connection *died*
	double deadConnectionDuration;//The maximum amount of time for which this
	//  connection has been *dead*

	//Timestamp Option Data
	bool usesTimestamps;
	bool checkedForTSOptions;
	uint32 currentTSVal;

	//Endpoint loss recovery state
	void setRecoveryState(RecoveryState state);
	RecoveryState recoveryState;

	uint32 sackedBytes;
	uint32 sackedSegments;

private:
	bool usesDelayedAcks;
	uint32 sendTimestampVal;
	uint32 echoTimestampVal;

	void ProcessSegment(SegmentInfo *tp);

	//This is an optimized function for searching whether a segment is already
	//  in the list, outstandingData.
	bool isMemberOutstanding(SequenceRange* seq);

	DuplicateAck* findDupAck(SequenceRange* seq, HashKey* key, Segment* segment);
	bool isResponse(double currentTime);
	//Is it likely that this retransmission is in response
	// to an acknowledgement that was recently observed?

	void updateSequenceGap(uint32 seq);

	void addRetransmission(SequenceRange* seq, Segment* packet);
	SCORE* scoreRetransmission(SequenceRange* seq, Segment* packet,
			RETRANSMISSION_REASON_CODE reason, HashKey* key);

	Segment* findLikelyOriginalsSegment(SequenceRange* seq);

	//Determines if the sequence wrapped around
	bool sequenceWrap(uint32 Xi, uint32 Xf);

	//Determines if Xf is less than or equal to the Xi if wrapped or not
	bool sequenceWrapLtEq(uint32 Xi, uint32 Xf);

	//Determines if Xf if less than Xi if wrapped or not
	bool sequenceWrapLt(uint32 Xi, uint32 Xf);

	void addForwardAckTS(double arg) {fackTimestamps[ ((fackCount++) % ACK_COUNT) ] = new double(arg);}

	ODRate deltaOutstandingData;    //Change in Outstanding Data from RTT to RTT
	GapInfo endpointGapInfo;//Gap checking heuristic data structure

	uint32 fackCount;
	CircularList<double> fackTimestamps;

	uint32 ackCount;
	CircularList<double> ackTimestamps;//The "ACK_COUNT" most recent acknowledgement

	uint32 rttNumValidSamples;//A count of the number of valid rtt samples that
							  //  has been observed by this side of the connection

	bool SACKEnabled;//Has this endpoint been observed using sack? Or was it in the syn

	double rtt;//round trip time between observation point and this
			   //  endpoint
	double rttvar;//rtt variance between observation point and endpoint
	double estimatedRTO;//Estimated value of Retransmission Timeout timer
	uint32 recoverySequence;//sequence to be acknowledged for recovery to end

	bool isRTO(SequenceRange* seq, Segment* segment,
			RETRANSMISSION_REASON_CODE reason, HashKey* key);

	double maximumRTO;
	double lastRetransmissionTS;// Timestamp of the last retransmission
	uint32 lastRetransmissionSeq;//Sequence number of last retransmission
	bool lastRetransmissionRTO;//Was the last retransmission a 'RTO'?
	bool lastSegmentRetransmitted;

	void processFastRetransmission(Segment* segment, SequenceRange* seq, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE type, double confidence);
	void processRTO(Segment* segment, SequenceRange* seq, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE type, double confidence);

	void processRetransmissionEvent(Segment* segment, HashKey* key, SequenceRange* seq, uint32 ts, RETRANSMISSION_REASON_CODE reason);
	void processOutOfOrderEvent(Segment* segment);
	void processAmbigousReordering(Segment* segment, SequenceRange* seq);

	void sequenceGapCheck(SequenceRange *seq, Segment *value, uint32 ts, HashKey* key);
	void sequenceAckCheck(SequenceRange *seq, Segment *value, HashKey* key, uint32 normalized_ack_seq);
	void sequenceTimestampCheck(SequenceRange* seq, Segment* value, uint32 ts, HashKey* key);

	// events we throw
	void throwUnknownRetransmissionEvent(Segment* segment, SequenceRange* seq, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE type, double confidence);
	void throwRetransmissionEvent(Segment* segment, uint32 seq, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype, double confidence);
	void throwFACKRetransmissionEvent( uint32 seq, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype );

	void throwDuplicateAckEvent( uint32 seq, uint32 retransmissionCount );
	void throwCongestionStateChangeEvent( CongestionState prev, CongestionState current );
	void throwConnectionDeadEvent( double length );
	void throwReorderingEvent( uint32 seq, double gap, double rtt, uint32 seq_difference);
	void throwAmbiguousReorderingEvent(uint32 seq, double gap, uint32 seq_difference);
	void throwRTTEstimateEvent();
	void throwSpuriousRetransmissionEvent( uint32 seq, double ts, RETRANSMISSION_REASON_CODE reason, RETRANSMISSION_TYPE_CODE rtype, double confidence);
	void throwLimitedTransmitEvent( uint32 seq );
	void throwFastRecoveryTransmitEvent( uint32 seq );

	std::queue<SegmentInfoPtr> queuedSegments;
};



double getLikelyMaxRTO(double previous, double current);

} } // namespace analyzer::*
#endif
