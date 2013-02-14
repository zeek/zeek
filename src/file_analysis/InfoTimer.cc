#include "Manager.h"
#include "Info.h"

using namespace file_analysis;

void InfoTimer::Dispatch(double t, int is_expire)
	{
	Info* info = file_mgr->Lookup(file_id);

	if ( ! info ) return;

	double last_active = info->LastActivityTime();
	double inactive_time = t > last_active ? t - last_active : 0.0;

	DBG_LOG(DBG_FILE_ANALYSIS, "Checking inactivity for %s, last active at %f, "
		    "inactive for %f", file_id.c_str(), last_active, inactive_time);

	if ( last_active == 0.0 )
		{
		// was created when network_time was zero, so re-schedule w/ valid time
		info->UpdateLastActivityTime();
		info->ScheduleInactivityTimer();
		return;
		}

	if ( inactive_time >= info->TimeoutInterval() )
		file_mgr->Timeout(file_id);
	else if ( ! is_expire )
		info->ScheduleInactivityTimer();
	}
