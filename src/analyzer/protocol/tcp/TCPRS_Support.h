/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */


#ifndef TCPRS_SUPPORT_H
#define TCPRS_SUPPORT_H

#include "util.h"
#include "List.h"

namespace analyzer { namespace tcp {

#define SEGMENT_RTT_UNKNOWN -1.0
#define TS_UNKNOWN -1.0
#define INDETERMINATE -0.0

#define RXMIT_THRESHOLD 3.0 //Sent this ack once, and then 3 more times.
#define K_CONST 4.0
#define MIN_RTO 1.0
#define SEQ_WRAP 4294000000u
#define ACK_COUNT 20        //Record and keep record of a maximum of 20
//  timestamps per dup ack.
#define DEFAULT_SZ 20
#define INITIAL_RTO 3.0

#define MINIMUM_SAMPLE_COUNT 2          //There atleast must be two valid rtt samples for
//  this connection

#define TRIPLE 2
#define DOUBLE 1

#define  UNDEFINED  -1
#define  IS_UNDEFINED(arg) (arg < 0)

#define  ALPHA_SRTT 0.125
#define  BETA_SRTT  0.250
#define  FAR_THRESHOLD -0.5
#define  NEAR_THRESHOLD 0.5

#define  NECESSARY               1.00

#define FOR_EACH_IN_CLIST(v, x)    for( uint32 v = 0; v < x.size(); v++)

#define r_loop_over_list(list, iterator)  \
	int iterator;	\
	for ( iterator = (list).length; iterator > 0; --iterator )

#define DBL_EQUIV(val1, val2) (fabs((val1) - (val2)) < 0.000001)

class TCP_Flags;
//Forward Declaration to clear a compilation ordering error


int Sequence_number_comparison(const uint32 s1, const uint32 s2);
int Reverse_sequence_range_comparison(const void *v1, const void *v2);


struct SequenceRange {
	uint32 min;		//equal to sequence number in TCP header, normalized
	uint32 to_ack;  //equal to seq + len in TCP header, normalized
};

//This enumeration defines the congestion state of the endpoint
typedef enum {
	CONGESTION_UNKNOWN,         //State Unknown , typical during analyzing the
								//  first few packets of a connection
	CONGESTION_3WHS,            //Endpoint is attempting 3WHS
	CONGESTION_SLOW_START,      //Endpoint is exhibiting behavior
								//  typical of slow start
	CONGESTION_AVOIDANCE,       //Endpoint is exhibiting behavior typical of
								//  the Congestion Avoidance state
	CONGESTION_CONN_CLOSE,      //Endpoint is attempting to close the connection
	CONGESTION_WINDOW_LIMITED,  //Endpoint is window limited
	CONGESTION_STEADY, 			//Endpoint is steadily sending data and not window-limited
	CONGESTION_ZERO_WINDOW,     //Endpoint has zero window
	CONGESTION_REPEATED_RETRANS,//Endpoint is continually repeating retransmissions
	CONGESTION_IDLE             //Endpoint has no data to send
} CongestionState;

typedef enum {
	RECOVERY_NORMAL,            //Endpoint is transmitting normally and is not
								//  attempting any form of loss recovery
	RECOVERY_FAST_RTX,          //Endpoint is using the fast retransmission
								//  mechanism to recovery
	RECOVERY_FACK,              //Endpoint is using forward acks
	RECOVERY_EARLY_RTX,         //Endpoint is using early retransmission
	RECOVERY_RTO,               //Endpoint is recovering from a RTO
	RECOVERY_UNKNOWN
} RecoveryState;

typedef enum {
	RSTATE_ENDPOINT_ALIVE,      //Endpoint has been observed sending packets
	RSTATE_ENDPOINT_DEAD,       //Endpoint has not been responding
	RSTATE_OBSERVING            //Endpoint has not yet responded to a packet
								// and is being observed
} RespState;

typedef enum {
	REXMIT_UNKNOWN = 0,        //This code should never be used but is available
	//  for testing purposes
	REXMIT_PREV_OBSERVED = 1, //This packet is currently part of the outstanding
	//  data and thus the packet reported is a rtx
	REXMIT_SPANS_PREVIOUS = 2, //This packet spans a packet that has been previously
	//  transmitted and thus is a rexmit
	REXMIT_PREV_ACKNOWLEDGED = 3, //This packet has been acknowledged already and must
	//  be a retransmission of data that the receiver has
	//  already seen.
	REXMIT_PARTIALLY_ACKED = 4, //This packet contains data that has been acknowledged
	//  by the receiver. This must be a retransmit

	//All rexmit reason codes below this line are for retransmission for which
	//  the original packet was never observed
	REXMIT_TIMESTAMP = 5,       //This packet was identified as a retransmission
	//  packet via the TCP Timestamps Option
	REXMIT_ACK = 6,             //This packet was identified as a retransmission
	//  packet via the monotonically increasing property of acks
	REXMIT_GAP = 7              //This packet was identified as a retransmission
//  packet via a sequence gap check heuristic
} RETRANSMISSION_REASON_CODE;

typedef enum {
	REORDER_UNKNOWN,            //This reason code should never be used but is
								//  available for testing purposes
	REORDER_TIMESTAMP,          //This packet was identified as an out of order
								//  packet via the TCP Timestamps Option
	REORDER_ACK,                //This packet was identified as an out of order
								//  packet via the monotonically increasing property of acks
	REORDER_GAP,                //This packet was identified as an out of order
								//  packet via the sequence gap check heuristic
	REORDER_AMBIGUOUS           //It is unknown whether this packet is
								//  an out of order packet or retransmission
} REORDERED_REASON_CODE;

typedef enum {
	RTYPE_UNKNOWN = 0,          //This type code should never be used but is
								//  available for testing purposes
	RTYPE_RTO = 1,              //Retransmission Timeout
	RTYPE_FAST_TRIPDUP = 2,     //Fast Retransmission based on a triple dup ack
	RTYPE_FAST_SPECULATIVE = 3, //Fast Retransmission based on speculated triple
								//  dup ack and/or small outstanding data
	RTYPE_EARLY_REXMIT = 4,   //Early retransmit based on small outstanding data
							  //  and new data segment sent after the second
							  //  duplicate acknowledgement
	RTYPE_REXMIT = 5,      //This retransmit is simply a recovery retransmission
	//  that occurred as a byproduct of a fast retransmission
	//  or retransmission timeout
	RTYPE_TESTING = 6,          //
	RTYPE_NO_RTT = 7,           //
	RTYPE_NO_TS = 8,            //
	RTYPE_SEG_EARLY_REXMIT = 9,     //
	RTYPE_BYTE_EARLY_REXMIT = 10,    //
	RTYPE_SACK_SEG_EARLY_REXMIT = 11,    //
	RTYPE_SACK_BYTE_EARLY_REXMIT = 12,    //
	RTYPE_SACK_BASED_RECOVERY = 13,   //
	RTYPE_BRUTE_FORCE_RTO = 14, //This is for a retransmission that has
								// forced as a retransmission more than once
	RTYPE_RTO_NO_DUPACK = 15,
	RTYPE_FACK_BASED = 16,
	RTYPE_COUNT = 17
} RETRANSMISSION_TYPE_CODE;

typedef enum {
	SR_LOST_ACK = 0, SR_UNKNOWN = 1
} SPURIOUS_REASON_CODE;

typedef struct _odrate {
	double timestamp;           //Timestamp of start of the measurement time
	double roundtrip;           //duration of measurement
	int64 prev_outstanding;     //previous max of outstanding data
	int64 curr_outstanding;     //Current max of outstanding data
	int64 prev_change;          //Previous change in outstanding data
	double rtx_timestamp;       //When did the retransmission occur?
} ODRate;

typedef struct _gap {
	double timestamp;           //When did this gap begin ?(In network time)
	double roundtrip;         //What was the round-trip time when the gap began?
	uint32 min;                 //Floor of the gap
	uint32 to_ack;              //Ceil of the gap
	uint32 segment_difference;  //number of segments out of order
} GapInfo;

typedef struct _segment {
	uint32 min;
	uint32 to_ack;
	double timestamp;
	double rtt2;
	double rttvar;
	bool necessary;
	double confidence;
	double original;
} SEGMENT;

typedef struct _ack {
	uint32 ack_seq;
	double timestamp;
	double rtt1;
	double rttvar;
	bool lost;
} ACK;

typedef struct __score {
	float confidence;
	RETRANSMISSION_TYPE_CODE type;
} SCORE;

typedef struct tcp_options {
	uint8 tcp_sack_permitted :1;
	uint8 tcp_max_segment_size :1;
	uint8 tcp_timestamp :1;
	uint8 tcp_sack_values :1;
	uint8 opt_sack_count :2;
	uint8 val_sack_permitted :1;
	uint16 val_mss;
	uint32 reserved :9; // Making this dword aligned
	uint32 val_sack_sequence[3];
	uint32 val_send_timestamp;
	uint32 val_echo_timestamp;

} TCP_OPTIONS;

typedef struct _SegmentInfo {
	uint32 len;
	uint16 segmentID;
	u_char ttl;
	u_char padding1;
	u_char *tp; /* maximum size of a tcp header is 60 bytes */
	double current_time; /* current time w.r.t. the packet */
	double time_to_process;
} SegmentInfo;

typedef SegmentInfo* SegmentInfoPtr;

typedef enum {
	ORDERING_UNKNOWN,
	ORDERING_NORMAL,
	ORDERING_REORDERED,
	ORDERING_RETRANSMISSION,
	ORDERING_AMBIGUOUS
} SEGMENT_ORDERING;


template<class T>
class CircularList {
public:
	CircularList(const bro_uint_t& SZ = DEFAULT_SZ) {
		arr = new T*[SZ];
		memset(arr, 0x0, sizeof(T*) * SZ);
		count = 0;
		max_size = SZ;
	}

	CircularList(const CircularList& other) {
		count = other.count;
		max_size = other.max_size;
		cleanup();
		arr = new T*[max_size];
		for (bro_uint_t i = 0; i < size(); i++) {
			if (other.arr[i] == NULL)
				arr[i] = NULL;
			else
				arr[i] = new T(other.arr[i]);
		}
	}

	~CircularList() {
		cleanup();
	}

	bool is_member(T* entry) {
		if (!entry)
			return false;

		for (bro_uint_t i = 0; i < size(); i++) {
			if (*entry == *(arr[i]))
				return true;
		}

		return false;
	}

	void addEntry(T* entry) {
		if (!arr[(count % max_size)])
			delete arr[(count % max_size)];

		arr[(count % max_size)] = entry;
		count++;
	}

	T*& operator [](const bro_uint_t& val) {
		return arr[(val % max_size)];
	}

	bro_uint_t size() const {
		return ((count > max_size) ? max_size : count);
	}

private:

	void cleanup() {
		for (bro_uint_t i = 0; i < size(); i++) {
			if (arr[i])
				delete arr[i];
		}
		delete[] arr;
	}

	T** arr;
	bro_uint_t count;
	bro_uint_t max_size;
};

//Implemented via section 5 in RFC 2988
class RTOTimer {
public:
	RTOTimer() {
		turnOff();
	}

	RTOTimer(const RTOTimer& copy) {
		ts = copy.ts;
		rto = copy.rto;
	}

	void updateRTOTimer(double current_time, double estimated_rto) {
		ts = current_time;
		rto = estimated_rto;
	}

	bool running() {
		return (ts > 0.0);
	}

	bool expired(double current_time) {
		return (running() && ((current_time - ts) >= rto));
	}

	void turnOff() {
		ts = UNDEFINED;
		rto = UNDEFINED;
	}

	double elapsedTime(double current_time) {
		return (current_time - ts);
	}

	double TS() {
		return ts;
	}
	double RTO() {
		return rto;
	}

private:
	double ts;
	double rto;
};

class DuplicateAck {
public:

	DuplicateAck(uint32 seq, double current_time);
	DuplicateAck(const DuplicateAck& copy);

	void updateDupAck(double arg);
	double getFirst() {
		return first;
	}
	double getLast() {
		return last;
	}
	//double getTS(int arg)             { return timestamps[(arg % ACK_COUNT)]; }
	double getTS(int arg) {
		if (timestamps[arg])
			return *timestamps[arg];
		return UNDEFINED;
	}

	uint32 getSeq() {
		return sequence;
	}

	uint32 getDupCount() {
		return dupCount;
	}

	void setFastRTX() {
		fastRTX = true;
	}
	bool isFastRTX() {
		return fastRTX;
	}

private:
	void setTS(double arg) {
		timestamps.addEntry(new double(arg));
	}

	double first;
	double last;
	uint32 sequence;

	uint32 dupCount;
	bool fastRTX;

	CircularList<double> timestamps;
};

/* There is some confusion about the meanings of some of these variables.
 *
 * Knowing when the original packet was transmitted may be crucial to some
 * heuristics. It may be prudent to set segmentSentTimestamp to undefined
 * if the original packet was never observed, or acknowledged previously
 * and dropped from memory due to maintaining minimal information about
 * the connection.
 *
 */
class Segment {
public:
	Segment(double t, int s, int id) {
		segmentSentTimestamp = t;
		byteCount = s;
		ackReceivedTimestamp = SEGMENT_RTT_UNKNOWN;
		reordered = false;
		fastRTX = false;
		numDupAck = 0;
		rtx = false;
		fin = false;
		syn = false;
		rst = false;
		original_observed = false;
		rtxCount = 0;
		packetID = id;
		ordering = ORDERING_NORMAL;
		tsCount = 1;
		timestamps[0] = t;
		reserved = 0;
		sentDuringLossRecovery = false;
	}

	void setAckReceivedTime(double t) {
		ackReceivedTimestamp = t;
	}
	double RTT() {
		return ackReceivedTimestamp - segmentSentTimestamp;
	}
	int getPacketSize() {
		return byteCount;
	}
	double getPacketSentTimestamp() {
		return segmentSentTimestamp;
	}
	double RTO() {
		return rto;
	}
	int duplicateCount() {
		return numDupAck;
	}
	void incrementDupCount() {
		numDupAck++;
	}
	void setOrdering(SEGMENT_ORDERING type) {
		ordering = type;
	}
	void setRTO(double r) {
		rto = r;
	}
	void setFastRTX() {
		fastRTX = true;
	}
	//void setRTX()                 { rtx = true; }
	void setFIN() {
		fin = true;
	}
	void setSYN() {
		syn = true;
	}
	void setRST() {
		rst = true;
	}
	//void setOutOfOrder()          { reordered = true; }
	SEGMENT_ORDERING getOrdering() {
		return ordering;
	}
	bool isFastRTX() {
		return fastRTX;
	}
	//bool isRTX()                  { return rtx; }
	bool isFIN() {
		return fin;
	}
	bool isSYN() {
		return syn;
	}
	bool isRST() {
		return rst;
	}
	//bool isOutOfOrder()           { return reordered; }
	int RTXCount() {
		return rtxCount;
	}
	void incrementRTX() {
		++rtxCount;
	}
	bool isHWDup(uint16 id) {
		return packetID == id;
	}
	uint16 getID() {
		return packetID;
	}
	void updateTimestamp(double arg) {
		timestamps[(tsCount) % ACK_COUNT] = arg;
		tsCount++;
	}
	double getLatestTimestamp() {
		return TS(tsCount);
	}
	double TS(int arg) {
		return timestamps[(arg - 1) % ACK_COUNT];
	}

	bool sentDuringLossRecovery;
	bool original_observed;			// was the first packet ever observed?
protected:

	double segmentSentTimestamp;     //When was the packet *originally* sent?
	double ackReceivedTimestamp;    //When was the packet actually acknowledged?
	uint32 byteCount;                  //Size of the packet in bytes
	uint32 numDupAck;                //The number of duplicate acks observed for
									 //  this packet
	double rto;                       //Estimated RTO for this packet
	bool fastRTX;
	bool rtx;                      //Is this packet a retransmission?
	bool fin;                      //Is this a fin packet?
	bool syn;                      //Is this a syn packet?
	bool rst;						 //Is this a reset?
	bool reordered;                //Did this packet appear out of order?
	SEGMENT_ORDERING ordering;
	uint32 rtxCount;                    //How many times was this retransmitted?
	uint32 tsCount;                 //How many timestamps have been recorded for
									//  this packet?
	uint16 packetID;
	uint16 reserved;
	double timestamps[ACK_COUNT]; //Timestamps for which the packet was observeds
};

/* List declarations */
declare(PList, uint32);
declare(PList, double);
declare(PList, SequenceRange);
declare(PList, Segment);
declare(PList, DuplicateAck);
declare(PList, CongestionState);
declare(PList, SEGMENT);
declare(PList, ACK);

} }

#endif
