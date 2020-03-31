// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Timer.h"

#include <string>

using std::string;

namespace file_analysis {

/**
 * Timer to periodically check if file analysis for a given file is inactive.
 */
class FileTimer : public Timer {
public:

	/**
	 * Constructor, nothing interesting about it.
	 * @param t unix time at which the timer should start ticking.
	 * @param id the file identifier which will be checked for inactivity.
	 * @param interval amount of time after \a t to check for inactivity.
	 */
	FileTimer(double t, const string& id, double interval);

	/**
	 * Check inactivity of file_analysis::File corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 * @param t current unix time
	 * @param is_expire true if all pending timers are being expired.
	 */
	void Dispatch(double t, bool is_expire) override;

private:
	string file_id;
};

} // namespace file_analysis
