// See the file "COPYING" in the main distribution directory for copyright.

#if defined(__linux__)

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <sched.h>

namespace zeek {
bool set_affinity(int core_number)
	{
	cpu_set_t cpus;
	CPU_ZERO(&cpus);
	CPU_SET(core_number, &cpus);
	auto res = sched_setaffinity(0, sizeof(cpus), &cpus);
	return res == 0;
	}
} // namespace zeek

#elif defined(__FreeBSD__)

#include <sys/param.h>
#include <sys/cpuset.h>

namespace zeek {
bool set_affinity(int core_number)
	{
	cpuset_t cpus;
	CPU_ZERO(&cpus);
	CPU_SET(core_number, &cpus);
	auto res = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
	                              sizeof(cpus), &cpus);
	return res == 0;
	}
} // namespace zeek

#else

#include <cerrno>

namespace zeek {
bool set_affinity(int core_number)
	{
	errno = ENOTSUP;
	return false;
	}
} // namespace zeek

#endif
