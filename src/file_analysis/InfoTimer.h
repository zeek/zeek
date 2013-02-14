#ifndef FILE_ANALYSIS_INFOTIMER_H
#define FILE_ANALYSIS_INFOTIMER_H

#include "Timer.h"
#include <string>

namespace file_analysis {

/**
 * Timer to periodically check if file analysis for a given file is inactive.
 */
class InfoTimer : public Timer {
public:

	InfoTimer(double t, const string& id, double interval)
	    : Timer(t + interval, TIMER_FILE_ANALYSIS_INACTIVITY), file_id(id) {}

	~InfoTimer() {}

	/**
	 * Check inactivity of file_analysis::Info corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 */
	void Dispatch(double t, int is_expire);

protected:

	string file_id;
};

} // namespace file_analysis

#endif
