// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h" // Needed for HAVE_LINUX

#include <cstdint>

namespace zeek::telemetry::detail {

struct process_stats {
    int64_t rss = 0;
    int64_t vms = 0;
    double cpu_user = 0.0;
    double cpu_system = 0.0;
    int64_t fds = 0;
};

#if defined(__APPLE__) || defined(HAVE_LINUX) || defined(__FreeBSD__)

#define HAVE_PROCESS_STAT_METRICS
process_stats get_process_stats();

#endif

} // namespace zeek::telemetry::detail
