#ifndef FILE_ANALYSIS_INFOTIMER_H
#define FILE_ANALYSIS_INFOTIMER_H

#include <string>
#include "Timer.h"
#include "FileID.h"

namespace file_analysis {

/**
 * Timer to periodically check if file analysis for a given file is inactive.
 */
class InfoTimer : public Timer {
public:

	InfoTimer(double t, const FileID& id, double interval)
	    : Timer(t + interval, TIMER_FILE_ANALYSIS_INACTIVITY), file_id(id) {}

	/**
	 * Check inactivity of file_analysis::Info corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 */
	void Dispatch(double t, int is_expire);

protected:

	FileID file_id;
};

} // namespace file_analysis

#endif
