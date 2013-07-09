// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_FILETIMER_H
#define FILE_ANALYSIS_FILETIMER_H

#include <string>
#include "Timer.h"

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
	void Dispatch(double t, int is_expire);

private:
	string file_id;
};

} // namespace file_analysis

#endif
