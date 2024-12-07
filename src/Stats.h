// See the file "COPYING" in the main distribution directory for copyright.

// Classes that collect and report statistics.

#pragma once

#include "zeek/zeek-config.h"

#include <cstdint>
#include <memory>

namespace zeek {

class File;

namespace detail {

class Location;

class ProfileLogger final {
public:
    ProfileLogger(zeek::File* file, double interval);
    ~ProfileLogger();

    void Log();
    zeek::File* File() { return file; }

private:
    zeek::File* file;
    unsigned int log_count;
};

extern std::shared_ptr<ProfileLogger> profiling_logger;

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

} // namespace detail
} // namespace zeek
