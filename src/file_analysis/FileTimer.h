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
	FileTimer(double t, const string& id, double interval);

	/**
	 * Check inactivity of file_analysis::File corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 */
	void Dispatch(double t, int is_expire);

private:
	string file_id;
};

} // namespace file_analysis

#endif
