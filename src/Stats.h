// Classes that collect and report statistics.

#pragma once

#include "zeek-config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>

namespace zeek { class File; }

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Location, zeek::detail);

namespace zeek::detail {

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
	    : reporter(arg_reporter), name(arg_name), loc(), initial_rusage()
		{
		if ( reporter )
			Init();
		}

	SegmentProfiler(SegmentStatsReporter* arg_reporter,
	                const Location* arg_loc)
	    : reporter(arg_reporter), name(), loc(arg_loc), initial_rusage()
		{
		if ( reporter )
			Init();
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


class ProfileLogger final : public SegmentStatsReporter {
public:
	ProfileLogger(zeek::File* file, double interval);
	~ProfileLogger() override;

	void Log();
	zeek::File* File()	{ return file; }

protected:
	void SegmentProfile(const char* name, const Location* loc,
	                    double dtime, int dmem) override;

private:
	zeek::File* file;
	unsigned int log_count;
};


// Generates load_sample() events.
class SampleLogger final : public SegmentStatsReporter {
public:
	SampleLogger();
	~SampleLogger() override;

	// These are called to report that a given function or location
	// has been seen during the sampling.
	void FunctionSeen(const Func* func);
	void LocationSeen(const Location* loc);

protected:
	void SegmentProfile(const char* name, const Location* loc,
	                    double dtime, int dmem) override;

	TableVal* load_samples;
};


extern ProfileLogger* profiling_logger;
extern ProfileLogger* segment_logger;
extern SampleLogger* sample_logger;

// Connection statistics.
extern uint64_t killed_by_inactivity;

// Content gap statistics.
extern uint64_t tot_ack_events;
extern uint64_t tot_ack_bytes;
extern uint64_t tot_gap_events;
extern uint64_t tot_gap_bytes;

class PacketProfiler {
public:
	PacketProfiler(unsigned int mode, double freq, File* arg_file);
	~PacketProfiler();

	static const unsigned int MODE_TIME = 1;
	static const unsigned int MODE_PACKET = 2;
	static const unsigned int MODE_VOLUME = 3;

	void ProfilePkt(double t, unsigned int bytes);

protected:
	File* file;
	unsigned int update_mode;
	double update_freq;
	double last_Utime, last_Stime, last_Rtime;
	double last_timestamp, time;
	uint64_t last_mem;
	uint64_t pkt_cnt;
	uint64_t byte_cnt;
};

} // namespace zeek::detail
