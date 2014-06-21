// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"
#include "File.h"

using namespace file_analysis;

FileTimer::FileTimer(double t, const string& id, double interval)
    : Timer(t + interval, TIMER_FILE_ANALYSIS_INACTIVITY), file_id(id)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "New %f second timeout timer for %s",
	        file_id.c_str(), interval);
	}

void FileTimer::Dispatch(double t, int is_expire)
	{
	File* file = file_mgr->LookupFile(file_id);

	if ( ! file )
		return;

	double last_active = file->GetLastActivityTime();
	double inactive_time = t > last_active ? t - last_active : 0.0;

	DBG_LOG(DBG_FILE_ANALYSIS, "Checking inactivity for %s, last active at %f, "
		    "inactive for %f", file_id.c_str(), last_active, inactive_time);

	if ( last_active == 0.0 )
		{
		// was created when network_time was zero, so re-schedule w/ valid time
		file->UpdateLastActivityTime();
		file->ScheduleInactivityTimer();
		return;
		}

	if ( inactive_time >= file->GetTimeoutInterval() )
		file_mgr->Timeout(file_id);
	else if ( ! is_expire )
		file->ScheduleInactivityTimer();
	}
