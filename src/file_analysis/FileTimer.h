// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include "zeek/Timer.h"

namespace zeek::file_analysis::detail {

/**
 * Timer to periodically check if file analysis for a given file is inactive.
 */
class FileTimer final : public zeek::detail::Timer {
public:

	/**
	 * Constructor, nothing interesting about it.
	 * @param t unix time at which the timer should start ticking.
	 * @param id the file identifier which will be checked for inactivity.
	 * @param interval amount of time after \a t to check for inactivity.
	 */
	FileTimer(double t, const std::string& id, double interval);

	/**
	 * Check inactivity of file_analysis::File corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 * @param t current unix time
	 * @param is_expire true if all pending timers are being expired.
	 */
	void Dispatch(double t, bool is_expire) override;

private:
	std::string file_id;
};

} // namespace zeek::file_analysis::detail
