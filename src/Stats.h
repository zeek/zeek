// $Id: Stats.h 6703 2009-05-13 22:27:44Z vern $
//
// Classes that collect and report statistics.

#ifndef STATS_H
#define STATS_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "TCP_Endpoint.h"


// Object called by SegmentProfiler when it is done and reports its
// cumulative CPU/memory statistics.
class SegmentStatsReporter {
public:
	SegmentStatsReporter()	{ }
	virtual ~SegmentStatsReporter()	{ }

	virtual void SegmentProfile(const char* name, const Location* loc,
					double dtime, int dmem) = 0;
};


// A SegmentProfiler tracks how much CPU and memory is consumed
// across its lifetime.
//
// ### This needs porting to Linux.  It could also be improved by
// better efforts at measuring its own overhead.
class SegmentProfiler {
public:
	// The constructor takes some way of identifying the segment.
	SegmentProfiler(SegmentStatsReporter* arg_reporter,
				const char* arg_name)
		{
		reporter = arg_reporter;
		if ( reporter )
			{
			name = arg_name;
			loc = 0;
			Init();
			}
		}

	SegmentProfiler(SegmentStatsReporter* arg_reporter,
				const Location* arg_loc)
		{
		reporter = arg_reporter;
		if ( reporter )
			{
			name = 0;
			loc = arg_loc;
			Init();
			}
		}

	~SegmentProfiler()
		{
		if ( reporter )
			Report();
		}

protected:
	void Init();
	void Report();

	SegmentStatsReporter* reporter;
	const char* name;
	const Location* loc;
	struct rusage initial_rusage;
};


class ProfileLogger : public SegmentStatsReporter {
public:
	ProfileLogger(BroFile* file, double interval);
	~ProfileLogger();

	void Log();
	BroFile* File()	{ return file; }

protected:
	void SegmentProfile(const char* name, const Location* loc,
				double dtime, int dmem);

private:
	BroFile* file;
	unsigned int log_count;
};


// Generates load_sample() events.
class SampleLogger : public SegmentStatsReporter {
public:
	SampleLogger();
	~SampleLogger();

	// These are called to report that a given function or location
	// has been seen during the sampling.
	void FunctionSeen(const Func* func);
	void LocationSeen(const Location* loc);

protected:
	void SegmentProfile(const char* name, const Location* loc,
				double dtime, int dmem);

	TableVal* load_samples;
};


extern ProfileLogger* profiling_logger;
extern ProfileLogger* segment_logger;
extern SampleLogger* sample_logger;

// Connection statistics.
extern int killed_by_inactivity;

// Content gap statistics.
extern uint32 tot_ack_events;
extern uint32 tot_ack_bytes;
extern uint32 tot_gap_events;
extern uint32 tot_gap_bytes;


// A TCPStateStats object tracks the distribution of TCP states for
// the currently active connections.  
class TCPStateStats {
public:
	TCPStateStats();
	~TCPStateStats() { }

	void ChangeState(EndpointState o_prev, EndpointState o_now,
				EndpointState r_prev, EndpointState r_now);
	void FlipState(EndpointState orig, EndpointState resp);

	void StateEntered (EndpointState o_state, EndpointState r_state)
		{ ++state_cnt[o_state][r_state]; }
	void StateLeft (EndpointState o_state, EndpointState r_state)
		{ --state_cnt[o_state][r_state]; }

	unsigned int Cnt(EndpointState state) const
		{ return Cnt(state, state); }
	unsigned int Cnt(EndpointState state1, EndpointState state2) const
		{ return state_cnt[state1][state2]; }

	unsigned int NumStateEstablished() const
		{ return Cnt(TCP_ENDPOINT_ESTABLISHED); }
	unsigned int NumStateHalfClose() const
		{ // corresponds to S2,S3
		return Cnt(TCP_ENDPOINT_ESTABLISHED, TCP_ENDPOINT_CLOSED) +
			Cnt(TCP_ENDPOINT_CLOSED, TCP_ENDPOINT_ESTABLISHED);
		}
	unsigned int NumStateHalfRst() const
		{
		return Cnt(TCP_ENDPOINT_ESTABLISHED, TCP_ENDPOINT_RESET) +
			Cnt(TCP_ENDPOINT_RESET, TCP_ENDPOINT_ESTABLISHED);
		}
	unsigned int NumStateClosed() const
		{ return Cnt(TCP_ENDPOINT_CLOSED); }
	unsigned int NumStateRequest() const
		{
		assert(Cnt(TCP_ENDPOINT_INACTIVE, TCP_ENDPOINT_SYN_SENT)==0);
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_INACTIVE);
		}
	unsigned int NumStateSuccRequest() const
		{
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_SYN_ACK_SENT) +
			Cnt(TCP_ENDPOINT_SYN_ACK_SENT, TCP_ENDPOINT_SYN_SENT);
		}
	unsigned int NumStateRstRequest() const
		{
		return Cnt(TCP_ENDPOINT_SYN_SENT, TCP_ENDPOINT_RESET) +
			Cnt(TCP_ENDPOINT_RESET, TCP_ENDPOINT_SYN_SENT);
		}
	unsigned int NumStateInactive() const
		{ return Cnt(TCP_ENDPOINT_INACTIVE); }
	unsigned int NumStatePartial() const;

	void PrintStats(BroFile* file, const char* prefix);

private:
	unsigned int state_cnt[TCP_ENDPOINT_RESET+1][TCP_ENDPOINT_RESET+1];
};

class PacketProfiler {
public:
	PacketProfiler(unsigned int mode, double freq, BroFile* arg_file);
	~PacketProfiler();

	static const unsigned int MODE_TIME = 1;
	static const unsigned int MODE_PACKET = 2;
	static const unsigned int MODE_VOLUME = 3;

	void ProfilePkt(double t, unsigned int bytes);

protected:
	BroFile* file;
	unsigned int update_mode;
	double update_freq;
	double last_Utime, last_Stime, last_Rtime;
	double last_timestamp, time;
	unsigned int last_mem;
	unsigned int pkt_cnt;
	unsigned int byte_cnt;
};

#endif
